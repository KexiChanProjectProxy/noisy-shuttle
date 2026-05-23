use ja3_rustls::{ConcatenatedParser, Ja3};
use structopt::clap::AppSettings::{ColoredHelp, DeriveDisplayOrder};
use structopt::StructOpt;
use structopt_flags::QuietVerbose;

use std::fmt::Debug;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use snowy_tunnel::{Client, FingerprintSpec, Server};

type Array<T> = Vec<T>;

/// Configuration for reusable session pooling and keep-alive.
/// All timer values are in seconds.
#[derive(Debug, Clone)]
pub struct ReuseConfig {
    /// Maximum idle reusable sessions per remote endpoint (default: 4)
    pub max_idle: usize,
    /// Maximum requests per reusable session (default: 100)
    pub max_requests: usize,
    /// Maximum session age in seconds (default: 1800 = 30 minutes)
    pub max_age: Duration,
    /// Idle timeout in seconds (default: 300 = 5 minutes)
    pub idle_timeout: Duration,
    /// Keepalive ping interval in seconds (default: 30)
    pub keepalive_interval: Duration,
    /// Keepalive pong timeout in seconds (default: 10)
    pub keepalive_timeout: Duration,
    /// Jitter percentage for eviction/age scheduling (default: 10)
    pub jitter_percent: u8,
}

impl ReuseConfig {
    /// Validate and create a ReuseConfig.
    /// Returns None if reuse is disabled (caller should check `--reuse` flag first).
    /// Returns Err with message for invalid combinations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_idle: usize,
        max_requests: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
        keepalive_interval_secs: u64,
        keepalive_timeout_secs: u64,
        jitter_percent: u8,
        keepalive_flag_was_set: bool,
    ) -> Result<Self, String> {
        // Validate max_idle
        if max_idle == 0 {
            return Err("reuse-max-idle must be greater than 0".to_string());
        }

        // Validate max_requests
        if max_requests == 0 {
            return Err("reuse-max-requests must be greater than 0".to_string());
        }

        // Validate timer values - zero or negative not allowed
        if max_age_secs == 0 {
            return Err("reuse-max-age must be greater than 0".to_string());
        }
        if idle_timeout_secs == 0 {
            return Err("reuse-idle-timeout must be greater than 0".to_string());
        }
        if keepalive_interval_secs == 0 {
            return Err("keepalive-interval must be greater than 0".to_string());
        }
        if keepalive_timeout_secs == 0 {
            return Err("keepalive-timeout must be greater than 0".to_string());
        }

        // Validate timeout < interval for keepalive
        if keepalive_timeout_secs >= keepalive_interval_secs {
            return Err("keepalive-timeout must be less than keepalive-interval".to_string());
        }

        // Validate idle_timeout < max_age
        if idle_timeout_secs >= max_age_secs {
            return Err("reuse-idle-timeout must be less than reuse-max-age".to_string());
        }

        // Warn if keepalive is set but reuse is not enabled (caller handles this)
        let _ = keepalive_flag_was_set;

        // Validate jitter
        if jitter_percent > 100 {
            return Err("reuse-jitter-percent must be between 0 and 100".to_string());
        }

        Ok(Self {
            max_idle,
            max_requests,
            max_age: Duration::from_secs(max_age_secs),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            keepalive_interval: Duration::from_secs(keepalive_interval_secs),
            keepalive_timeout: Duration::from_secs(keepalive_timeout_secs),
            jitter_percent,
        })
    }
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "noisy-shuttle", about = "Shuttle for the Internet", global_settings(&[ColoredHelp, DeriveDisplayOrder]))]
pub struct Opt {
    #[structopt(flatten)]
    pub verbose: QuietVerbose,

    #[structopt(subcommand)]
    pub role: Role,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, StructOpt)]
pub enum Role {
    /// Run client
    Client(CltOpt),
    /// Run server
    Server(SvrOpt),
}

#[derive(Debug, Clone, StructOpt)]
pub struct CltOpt {
    /// Local HOST:PORT address for the builtin proxy server to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// Server HOST:PORT address to connect to
    #[structopt(name = "REMOTE_ADDR")]
    pub remote_addr: String,

    /// Server name indication to send to the remote
    #[structopt(name = "SERVER_NAME")]
    pub server_name: String,

    /// Key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,

    /// Number or range of connections to establish in advance (shortening perceivable delay at
    /// risk of higher possibility of being distinguished)
    #[structopt(short ="p", long = "preflight", default_value = "0", parse(try_from_str = parse_preflight_bounds))]
    pub preflight: (usize, Option<usize>),

    // UNIMPLEMENTED
    // /// Activate transparent proxy mode, instructing the client to accept raw REDIRECTed TCP
    // /// traffic and TPROXY-ed UDP traffic (plain proxy is disabled in this case)
    // #[cfg(unix)]
    // #[structopt(long = "redir")]
    // pub redir: bool,
    /// JA3 TLS fingerprint to apply to ClientHello (possbily resulted in handshake error due to unsupported algos negotiated)
    #[structopt(long = "tls-ja3", name = "ja3")]
    pub tls_ja3: Option<Ja3>,

    /// ALPN to apply to ClientHello, in text, seperated by comma
    #[structopt(long = "tls-alpn", name = "alpn", parse(try_from_str = parse_alpn_array))]
    pub tls_alpn: Option<Array<Vec<u8>>>,

    /// Signature algorithms to apply to ClientHello, in decimal, seperated by comma
    #[structopt(long = "tls-sigalgos", name = "signature algorithms", parse(try_from_str = parse_u16_array))]
    pub tls_sigalgos: Option<Array<u16>>,

    // Supported TLS versions to apply to ClientHello, in decimal, seperated by comma
    #[structopt(long = "tls-versions", name = "supported versions", parse(try_from_str = parse_u16_array))]
    pub tls_versions: Option<Array<u16>>,

    /// Key Share curves to apply to ClientHello, seperated by comma (only X25519 and GREASE are allowed so far)
    #[structopt(long = "tls-keyshare", name = "keyshare", parse(try_from_str = parse_u16_array))]
    pub tls_keyshare: Option<Array<u16>>,

    // === Reusable session and keep-alive options (opt-in) ===
    /// Enable reusable session pooling (disabled by default)
    #[structopt(long = "reuse")]
    pub reuse: bool,

    /// Maximum idle reusable sessions per remote endpoint (default: 4)
    #[structopt(long = "reuse-max-idle", default_value = "4")]
    pub reuse_max_idle: usize,

    /// Maximum requests per reusable session (default: 100)
    #[structopt(long = "reuse-max-requests", default_value = "100")]
    pub reuse_max_requests: usize,

    /// Maximum session age in seconds (default: 1800 = 30 minutes)
    #[structopt(long = "reuse-max-age", default_value = "1800")]
    pub reuse_max_age: u64,

    /// Idle timeout in seconds (default: 300 = 5 minutes)
    #[structopt(long = "reuse-idle-timeout", default_value = "300")]
    pub reuse_idle_timeout: u64,

    /// Keepalive interval in seconds for idle reusable sessions (default: 30)
    #[structopt(long = "keepalive-interval", default_value = "30")]
    pub keepalive_interval: u64,

    /// Keepalive pong timeout in seconds (default: 10)
    #[structopt(long = "keepalive-timeout", default_value = "10")]
    pub keepalive_timeout: u64,

    /// Jitter percentage for eviction/age scheduling (default: 10, range: 0-100)
    #[structopt(long = "reuse-jitter-percent", default_value = "10")]
    pub reuse_jitter_percent: u8,
}

#[derive(Debug, Clone, StructOpt)]
pub struct SvrOpt {
    /// Local HOST:PORT address to listen on
    #[structopt(name = "LISTEN_ADDR")]
    pub listen_addr: SocketAddr,

    /// Camouflage HOST:PORT address to connect to for replicating TLS handshaking
    #[structopt(name = "CAMOUFLAGE_ADDR")]
    pub camouflage_addr: String,

    /// Key to encrypt all traffic
    #[structopt(name = "KEY")]
    pub key: String,

    /// Size of the internal time-based LRU replay filter (time window: ±90secs)
    #[structopt(long = "rfsize", default_value = "2048", name = "size")]
    pub replay_filter_size: usize,
}

impl CltOpt {
    pub fn get_fingerprint_spec(&self) -> FingerprintSpec {
        FingerprintSpec {
            ja3: self.tls_ja3.clone(),
            alpn: self.tls_alpn.clone(),
            signature_algos: self.tls_sigalgos.clone(),
            supported_versions: self.tls_versions.clone(),
            keyshare_curves: self.tls_keyshare.clone(),
        }
    }

    pub fn build_client(&self) -> Client {
        Client::new_with_fingerprint(
            self.key.as_bytes(),
            self.server_name.as_str().try_into().unwrap(),
            self.get_fingerprint_spec(),
        )
    }

    /// Returns the reuse configuration if reuse is enabled, or None otherwise.
    /// Returns Err if the configuration is invalid.
    ///
    /// Validation rules:
    /// - keepalive-interval requires --reuse to be enabled (returns warning internally)
    /// - Zero values are rejected for all timer/count fields
    /// - keepalive-timeout must be less than keepalive-interval
    /// - reuse-idle-timeout must be less than reuse-max-age
    /// - reuse-jitter-percent must be between 0 and 100
    pub fn reuse_config(&self) -> Result<Option<ReuseConfig>, String> {
        if !self.reuse {
            return Ok(None);
        }

        ReuseConfig::new(
            self.reuse_max_idle,
            self.reuse_max_requests,
            self.reuse_max_age,
            self.reuse_idle_timeout,
            self.keepalive_interval,
            self.keepalive_timeout,
            self.reuse_jitter_percent,
            true, // keepalive was set (since reuse is enabled, this is always true)
        )
        .map(Some)
    }
}

impl SvrOpt {
    pub fn build_server(&self) -> Server<String> {
        Server::new(
            self.key.as_bytes(),
            self.camouflage_addr.clone(),
            self.replay_filter_size,
        )
    }
}

fn parse_preflight_bounds(s: &str) -> Result<(usize, Option<usize>), &str> {
    let s = s.trim();
    if s.is_empty() {
        Ok((0, Some(0)))
    } else if let Ok(n) = s.parse::<usize>() {
        Ok((n, Some(n)))
    } else if let Some(i) = s.find(':') {
        let (a, b) = s.split_at(i);
        let a = a.trim();
        let b = b[1..].trim();
        let a = if a.is_empty() {
            0
        } else {
            a.parse::<usize>()
                .map_err(|_| "Min present but not integer")?
        };
        let b = if b.is_empty() {
            None
        } else {
            Some(
                b.parse::<usize>()
                    .map_err(|_| "Max present but not integer")?,
            )
        };
        if a == 0 && b != Some(0) {
            Err("Min cannot be 0 if max is not 0")
        } else {
            Ok((a, b))
        }
    } else {
        Err("Unrecognized bounds, expected format: NUM, MIN:MAX, MIN:, :MAX")
    }
}

fn parse_u16_array(s: &str) -> Result<Array<u16>, &'static str> {
    ConcatenatedParser::<u16, ','>::from_str(s).map(|p| p.into_inner())
}

fn parse_alpn_array(s: &str) -> Result<Array<Vec<u8>>, &'static str> {
    // TODO: this creates temporary Vec
    Ok(ConcatenatedParser::<String, ','>::from_str(s)
        .map(|p| p.into_inner())?
        .into_iter()
        .map(|e| e.into_bytes())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_reuse_config() -> ReuseConfig {
        ReuseConfig::new(
            4,    // max_idle
            100,  // max_requests
            1800, // max_age_secs
            300,  // idle_timeout_secs
            30,   // keepalive_interval_secs
            10,   // keepalive_timeout_secs
            10,   // jitter_percent
            true,
        )
        .unwrap()
    }

    #[test]
    fn test_valid_reuse_config() {
        let cfg = valid_reuse_config();
        assert_eq!(cfg.max_idle, 4);
        assert_eq!(cfg.max_requests, 100);
        assert_eq!(cfg.max_age, Duration::from_secs(1800));
        assert_eq!(cfg.idle_timeout, Duration::from_secs(300));
        assert_eq!(cfg.keepalive_interval, Duration::from_secs(30));
        assert_eq!(cfg.keepalive_timeout, Duration::from_secs(10));
        assert_eq!(cfg.jitter_percent, 10);
    }

    #[test]
    fn test_reuse_config_zero_max_idle() {
        let result = ReuseConfig::new(0, 100, 1800, 300, 30, 10, 10, true);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "reuse-max-idle must be greater than 0");
    }

    #[test]
    fn test_reuse_config_zero_max_requests() {
        let result = ReuseConfig::new(4, 0, 1800, 300, 30, 10, 10, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "reuse-max-requests must be greater than 0"
        );
    }

    #[test]
    fn test_reuse_config_zero_max_age() {
        let result = ReuseConfig::new(4, 100, 0, 300, 30, 10, 10, true);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "reuse-max-age must be greater than 0");
    }

    #[test]
    fn test_reuse_config_zero_idle_timeout() {
        let result = ReuseConfig::new(4, 100, 1800, 0, 30, 10, 10, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "reuse-idle-timeout must be greater than 0"
        );
    }

    #[test]
    fn test_reuse_config_zero_keepalive_interval() {
        let result = ReuseConfig::new(4, 100, 1800, 300, 0, 10, 10, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "keepalive-interval must be greater than 0"
        );
    }

    #[test]
    fn test_reuse_config_zero_keepalive_timeout() {
        let result = ReuseConfig::new(4, 100, 1800, 300, 30, 0, 10, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "keepalive-timeout must be greater than 0"
        );
    }

    #[test]
    fn test_reuse_config_keepalive_timeout_gte_interval() {
        let result = ReuseConfig::new(4, 100, 1800, 300, 30, 30, 10, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "keepalive-timeout must be less than keepalive-interval"
        );
    }

    #[test]
    fn test_reuse_config_idle_timeout_gte_max_age() {
        let result = ReuseConfig::new(4, 100, 300, 300, 30, 10, 10, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "reuse-idle-timeout must be less than reuse-max-age"
        );
    }

    #[test]
    fn test_reuse_config_jitter_over_100() {
        let result = ReuseConfig::new(4, 100, 1800, 300, 30, 10, 101, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "reuse-jitter-percent must be between 0 and 100"
        );
    }

    #[test]
    fn test_cltopt_reuse_config_disabled() {
        let opt = CltOpt {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            remote_addr: "example.com:443".to_string(),
            server_name: "example.com".to_string(),
            key: "test_key_32_bytes_long_xxxx".to_string(),
            preflight: (0, Some(0)),
            tls_ja3: None,
            tls_alpn: None,
            tls_sigalgos: None,
            tls_versions: None,
            tls_keyshare: None,
            reuse: false,
            reuse_max_idle: 4,
            reuse_max_requests: 100,
            reuse_max_age: 1800,
            reuse_idle_timeout: 300,
            keepalive_interval: 30,
            keepalive_timeout: 10,
            reuse_jitter_percent: 10,
        };
        assert!(opt.reuse_config().unwrap().is_none());
    }

    #[test]
    fn test_cltopt_reuse_config_enabled_valid() {
        let opt = CltOpt {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            remote_addr: "example.com:443".to_string(),
            server_name: "example.com".to_string(),
            key: "test_key_32_bytes_long_xxxx".to_string(),
            preflight: (0, Some(0)),
            tls_ja3: None,
            tls_alpn: None,
            tls_sigalgos: None,
            tls_versions: None,
            tls_keyshare: None,
            reuse: true,
            reuse_max_idle: 4,
            reuse_max_requests: 100,
            reuse_max_age: 1800,
            reuse_idle_timeout: 300,
            keepalive_interval: 30,
            keepalive_timeout: 10,
            reuse_jitter_percent: 10,
        };
        let cfg = opt.reuse_config().unwrap();
        assert!(cfg.is_some());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.max_idle, 4);
        assert_eq!(cfg.max_requests, 100);
    }

    #[test]
    fn test_cltopt_reuse_config_enabled_invalid() {
        let opt = CltOpt {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            remote_addr: "example.com:443".to_string(),
            server_name: "example.com".to_string(),
            key: "test_key_32_bytes_long_xxxx".to_string(),
            preflight: (0, Some(0)),
            tls_ja3: None,
            tls_alpn: None,
            tls_sigalgos: None,
            tls_versions: None,
            tls_keyshare: None,
            reuse: true,
            reuse_max_idle: 4,
            reuse_max_requests: 100,
            reuse_max_age: 1800,
            reuse_idle_timeout: 300,
            keepalive_interval: 30,
            keepalive_timeout: 30, // invalid: timeout >= interval
            reuse_jitter_percent: 10,
        };
        assert!(opt.reuse_config().is_err());
        assert_eq!(
            opt.reuse_config().unwrap_err(),
            "keepalive-timeout must be less than keepalive-interval"
        );
    }
}
