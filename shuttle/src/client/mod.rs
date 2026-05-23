use anyhow::Result;

use tracing::{debug, info, warn};

use std::sync::Arc;
use std::time::Duration;

use crate::opt::CltOpt;

mod connector;
mod plain;
pub mod pool;
// mod redir; // UNIMPLEMENTED

use self::connector::{AdHocConnector, Preflighter, PREFLIHGTER_CONNIDLE, PREFLIHGTER_EMA_COEFF};
use self::plain::serve as serve_plain;
use self::pool::SessionPool;

/// Maximum size of the initial data from inbound TCP socket which would be sent together with
/// request header
const MAX_FIRST_PACKET_SIZE: usize = 8192;
/// Time to wait for the initial data from inbound TCP socket which would be sent together with
/// request header
const FIRST_PACKET_TIMEOUT: Duration = Duration::from_millis(20);

pub async fn run_client(opt: CltOpt) -> Result<()> {
    warn!(
        "client listens at {} with remote: {}, sni: {}, preflight: {}-{}",
        &opt.listen_addr,
        &opt.remote_addr,
        &opt.server_name,
        &opt.preflight.0,
        &opt.preflight.1.unwrap_or(usize::MAX),
    );
    debug!(
        connidle = PREFLIHGTER_CONNIDLE,
        aht_ema_coeff = PREFLIHGTER_EMA_COEFF
    );
    let client = opt.build_client();
    if !client.fingerprint_spec.is_empty() {
        info!("tls fingerprint loaded");
        debug!(fpspec = ?client.fingerprint_spec);
    }

    match opt.preflight {
        (0, Some(0)) => {
            let remote_addr = opt.remote_addr.clone();
            let connector = Arc::new(AdHocConnector::new(client, remote_addr.clone()));
            let pool = opt
                .reuse_config()
                .map_err(anyhow::Error::msg)?
                .map(|config| Arc::new(SessionPool::new(config, Box::new(connector.clone()))));
            serve_plain(opt.listen_addr, connector, pool, remote_addr).await?;
        }
        (min, max) => {
            let remote_addr = opt.remote_addr.clone();
            let preflighter = Arc::new(Preflighter::new_flighting(
                client,
                remote_addr.clone(),
                min,
                max,
            ));
            let pool = opt
                .reuse_config()
                .map_err(anyhow::Error::msg)?
                .map(|config| Arc::new(SessionPool::new(config, Box::new(preflighter.clone()))));
            serve_plain(opt.listen_addr, preflighter, pool, remote_addr).await?;
        }
    };
    Ok(())
}
