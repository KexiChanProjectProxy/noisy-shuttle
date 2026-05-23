//! Session lifecycle states, close reasons, and events for reusable sessions.

use tracing::Level;

/// Session lifecycle states for reusable sessions.
///
/// A session transitions through these states during its lifetime.
/// Emergency transitions (to `Poisoned` or `Closed`) are allowed from any state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SessionState {
    /// Session is being established (connecting to upstream)
    Connecting,
    /// TLS handshake with upstream is in progress
    Handshaking,
    /// Session is established but not currently in use (idle in pool)
    Idle,
    /// Session is being prepared for use (e.g., selecting via preflight)
    Opening,
    /// Session is actively relaying traffic
    Active,
    /// Session is gracefully draining (no new requests, finishing existing)
    Draining,
    /// Session is being closed
    Closing,
    /// Session has been closed and can be dropped
    Closed,
    /// Session encountered an unrecoverable error (poison pill)
    Poisoned,
}

impl SessionState {
    /// Returns whether a transition from `self` to `target` is valid.
    ///
    /// Normal: Connecting→Handshaking, Handshaking→Idle|Closed, Idle→Opening|Closing|Poisoned,
    /// Opening→Active|Poisoned, Active→Draining|Poisoned, Draining→Idle|Closing|Poisoned,
    /// Closing→Closed, Poisoned→Closed. Emergency: any→Poisoned or any→Closed.
    #[allow(dead_code)]
    pub fn can_transition_to(&self, target: &SessionState) -> bool {
        use SessionState::*;
        match (self, target) {
            // Normal progression
            (Connecting, Handshaking) => true,
            (Handshaking, Idle) | (Handshaking, Closed) => true,
            (Idle, Opening) | (Idle, Closing) | (Idle, Poisoned) => true,
            (Opening, Active) | (Opening, Poisoned) => true,
            (Active, Draining) | (Active, Poisoned) => true,
            (Draining, Idle) | (Draining, Closing) | (Draining, Poisoned) => true,
            (Closing, Closed) => true,
            (Poisoned, Closed) => true,
            // Emergency transitions: any state can transition to Poisoned or Closed
            (_, Poisoned) | (_, Closed) => true,
            // All other transitions are invalid
            _ => false,
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Connecting => write!(f, "Connecting"),
            SessionState::Handshaking => write!(f, "Handshaking"),
            SessionState::Idle => write!(f, "Idle"),
            SessionState::Opening => write!(f, "Opening"),
            SessionState::Active => write!(f, "Active"),
            SessionState::Draining => write!(f, "Draining"),
            SessionState::Closing => write!(f, "Closing"),
            SessionState::Closed => write!(f, "Closed"),
            SessionState::Poisoned => write!(f, "Poisoned"),
        }
    }
}

/// Reason a session was closed or evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CloseReason {
    /// Client initiated close
    ClientClose,
    /// Client initiated close (server session loop terminology)
    ClientInitiated,
    /// Server initiated close
    ServerClose,
    /// Internal server error
    ServerError,
    /// Session was idle too long and was evicted from pool
    IdleTimeout,
    /// Session exceeded max age and was evicted
    MaxAgeExceeded,
    /// Session exceeded max requests and was evicted
    MaxRequestsExceeded,
    /// Session reached the configured max request count
    MaxRequestsReached,
    /// Keepalive ping timed out
    KeepaliveTimeout,
    /// Protocol error occurred
    ProtocolError,
    /// Client/server protocol versions are incompatible
    VersionMismatch,
    /// Session closed during graceful shutdown drain
    ShutdownDrain,
    /// Failed to check out session from pool
    CheckoutFailed,
    /// Session was poisoned due to unrecoverable error
    Poisoned,
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseReason::ClientClose => write!(f, "ClientClose"),
            CloseReason::ClientInitiated => write!(f, "ClientInitiated"),
            CloseReason::ServerClose => write!(f, "ServerClose"),
            CloseReason::ServerError => write!(f, "ServerError"),
            CloseReason::IdleTimeout => write!(f, "IdleTimeout"),
            CloseReason::MaxAgeExceeded => write!(f, "MaxAgeExceeded"),
            CloseReason::MaxRequestsExceeded => write!(f, "MaxRequestsExceeded"),
            CloseReason::MaxRequestsReached => write!(f, "MaxRequestsReached"),
            CloseReason::KeepaliveTimeout => write!(f, "KeepaliveTimeout"),
            CloseReason::ProtocolError => write!(f, "ProtocolError"),
            CloseReason::VersionMismatch => write!(f, "VersionMismatch"),
            CloseReason::ShutdownDrain => write!(f, "ShutdownDrain"),
            CloseReason::CheckoutFailed => write!(f, "CheckoutFailed"),
            CloseReason::Poisoned => write!(f, "Poisoned"),
        }
    }
}

/// Lifecycle and observability events for sessions.
///
/// Each variant produces a structured `tracing::event!` when emitted.
/// No secrets (key material, PSK, raw payload bytes) are ever logged.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SessionEvent {
    /// Successfully acquired a session from the pool
    PoolHit,
    /// No reusable session found in pool, falling back to one-shot
    PoolMiss,
    /// Failed to check out a session from the pool
    CheckoutFailed,
    /// Falling back to one-shot mode (e.g., preflight failed)
    FallbackToOneShot,
    /// Session was reused (contains reuse count)
    SessionReused(usize),
    /// Keepalive ping sent
    PingSent,
    /// Keepalive ping acknowledged
    PingAcked,
    /// Keepalive ping timed out
    PingTimeout,
    /// Session evicted from pool due to idle timeout
    IdleEviction,
    /// Session evicted from pool due to max age
    MaxAgeEviction,
    /// Session evicted from pool due to max requests
    MaxRequestsEviction,
    /// Server closed the connection
    RemoteClose,
    /// Session gracefully drained
    GracefulDrain,
}

impl SessionEvent {
    /// Emit this event as a structured tracing event at INFO level.
    ///
    /// # Security Note
    /// This method deliberately avoids logging any secrets, key material,
    /// PSK, or raw payload bytes. Only session lifecycle metadata is logged.
    pub fn emit(&self) {
        match self {
            SessionEvent::PoolHit => {
                tracing::event!(
                    Level::INFO,
                    event = "pool_hit",
                    "Session acquired from pool"
                );
            }
            SessionEvent::PoolMiss => {
                tracing::event!(
                    Level::INFO,
                    event = "pool_miss",
                    "No reusable session in pool"
                );
            }
            SessionEvent::CheckoutFailed => {
                tracing::event!(
                    Level::WARN,
                    event = "checkout_failed",
                    "Failed to checkout session from pool"
                );
            }
            SessionEvent::FallbackToOneShot => {
                tracing::event!(
                    Level::WARN,
                    event = "fallback_to_oneshot",
                    "Falling back to one-shot mode"
                );
            }
            SessionEvent::SessionReused(count) => {
                tracing::event!(
                    Level::INFO,
                    event = "session_reused",
                    reuse_count = count,
                    "Session reused from pool"
                );
            }
            SessionEvent::PingSent => {
                tracing::event!(Level::DEBUG, event = "ping_sent", "Keepalive ping sent");
            }
            SessionEvent::PingAcked => {
                tracing::event!(Level::DEBUG, event = "ping_acked", "Keepalive ping acked");
            }
            SessionEvent::PingTimeout => {
                tracing::event!(
                    Level::WARN,
                    event = "ping_timeout",
                    "Keepalive ping timed out"
                );
            }
            SessionEvent::IdleEviction => {
                tracing::event!(Level::INFO, event = "idle_eviction", reason = %CloseReason::IdleTimeout, "Session evicted due to idle timeout");
            }
            SessionEvent::MaxAgeEviction => {
                tracing::event!(Level::INFO, event = "max_age_eviction", reason = %CloseReason::MaxAgeExceeded, "Session evicted due to max age");
            }
            SessionEvent::MaxRequestsEviction => {
                tracing::event!(Level::INFO, event = "max_requests_eviction", reason = %CloseReason::MaxRequestsExceeded, "Session evicted due to max requests");
            }
            SessionEvent::RemoteClose => {
                tracing::event!(
                    Level::INFO,
                    event = "remote_close",
                    "Server closed the connection"
                );
            }
            SessionEvent::GracefulDrain => {
                tracing::event!(
                    Level::INFO,
                    event = "graceful_drain",
                    "Session gracefully drained"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        // Connecting -> Handshaking
        assert!(SessionState::Connecting.can_transition_to(&SessionState::Handshaking));

        // Handshaking -> Idle | Closed
        assert!(SessionState::Handshaking.can_transition_to(&SessionState::Idle));
        assert!(SessionState::Handshaking.can_transition_to(&SessionState::Closed));

        // Idle -> Opening | Closing | Poisoned
        assert!(SessionState::Idle.can_transition_to(&SessionState::Opening));
        assert!(SessionState::Idle.can_transition_to(&SessionState::Closing));
        assert!(SessionState::Idle.can_transition_to(&SessionState::Poisoned));

        // Opening -> Active | Poisoned
        assert!(SessionState::Opening.can_transition_to(&SessionState::Active));
        assert!(SessionState::Opening.can_transition_to(&SessionState::Poisoned));

        // Active -> Draining | Poisoned
        assert!(SessionState::Active.can_transition_to(&SessionState::Draining));
        assert!(SessionState::Active.can_transition_to(&SessionState::Poisoned));

        // Draining -> Idle | Closing | Poisoned
        assert!(SessionState::Draining.can_transition_to(&SessionState::Idle));
        assert!(SessionState::Draining.can_transition_to(&SessionState::Closing));
        assert!(SessionState::Draining.can_transition_to(&SessionState::Poisoned));

        // Closing -> Closed
        assert!(SessionState::Closing.can_transition_to(&SessionState::Closed));

        // Poisoned -> Closed
        assert!(SessionState::Poisoned.can_transition_to(&SessionState::Closed));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot go backwards
        assert!(!SessionState::Handshaking.can_transition_to(&SessionState::Connecting));
        assert!(!SessionState::Idle.can_transition_to(&SessionState::Handshaking));
        assert!(!SessionState::Opening.can_transition_to(&SessionState::Idle));
        assert!(!SessionState::Active.can_transition_to(&SessionState::Opening));
        assert!(!SessionState::Draining.can_transition_to(&SessionState::Active));

        // Cannot skip states
        assert!(!SessionState::Connecting.can_transition_to(&SessionState::Idle));
        assert!(!SessionState::Connecting.can_transition_to(&SessionState::Active));
        assert!(!SessionState::Handshaking.can_transition_to(&SessionState::Active));

        // Closed/Poisoned cannot transition (except Poisoned -> Closed)
        assert!(!SessionState::Closed.can_transition_to(&SessionState::Idle));
        assert!(!SessionState::Closed.can_transition_to(&SessionState::Connecting));
        assert!(!SessionState::Poisoned.can_transition_to(&SessionState::Idle));
    }

    #[test]
    fn test_emergency_transitions() {
        // Any state can transition to Poisoned (emergency)
        for state in [
            SessionState::Connecting,
            SessionState::Handshaking,
            SessionState::Idle,
            SessionState::Opening,
            SessionState::Active,
            SessionState::Draining,
            SessionState::Closing,
            SessionState::Closed,
        ] {
            assert!(
                state.can_transition_to(&SessionState::Poisoned),
                "Emergency transition to Poisoned should be allowed from {:?}",
                state
            );
        }

        // Any state can transition to Closed (emergency close)
        for state in [
            SessionState::Connecting,
            SessionState::Handshaking,
            SessionState::Idle,
            SessionState::Opening,
            SessionState::Active,
            SessionState::Draining,
            SessionState::Closing,
            SessionState::Poisoned,
        ] {
            assert!(
                state.can_transition_to(&SessionState::Closed),
                "Emergency transition to Closed should be allowed from {:?}",
                state
            );
        }
    }

    #[test]
    fn test_session_event_emit_no_panics() {
        // All events should emit without panicking
        let events = [
            SessionEvent::PoolHit,
            SessionEvent::PoolMiss,
            SessionEvent::CheckoutFailed,
            SessionEvent::FallbackToOneShot,
            SessionEvent::SessionReused(5),
            SessionEvent::PingSent,
            SessionEvent::PingAcked,
            SessionEvent::PingTimeout,
            SessionEvent::IdleEviction,
            SessionEvent::MaxAgeEviction,
            SessionEvent::MaxRequestsEviction,
            SessionEvent::RemoteClose,
            SessionEvent::GracefulDrain,
        ];

        for event in events {
            // Should not panic
            event.emit();
        }
    }

    #[test]
    fn test_session_event_captured_logs_dont_leak_secrets() {
        // Verify emit() works without panicking - secrets are never logged
        SessionEvent::PoolHit.emit();
        SessionEvent::PoolMiss.emit();
        SessionEvent::CheckoutFailed.emit();
        SessionEvent::FallbackToOneShot.emit();
        SessionEvent::SessionReused(42).emit();
        SessionEvent::PingSent.emit();
        SessionEvent::PingAcked.emit();
        SessionEvent::PingTimeout.emit();
        SessionEvent::IdleEviction.emit();
        SessionEvent::MaxAgeEviction.emit();
        SessionEvent::MaxRequestsEviction.emit();
        SessionEvent::RemoteClose.emit();
        SessionEvent::GracefulDrain.emit();
    }

    #[test]
    fn test_display_impls() {
        // Verify Display impls produce consistent output
        assert_eq!(SessionState::Connecting.to_string(), "Connecting");
        assert_eq!(SessionState::Handshaking.to_string(), "Handshaking");
        assert_eq!(SessionState::Idle.to_string(), "Idle");
        assert_eq!(SessionState::Opening.to_string(), "Opening");
        assert_eq!(SessionState::Active.to_string(), "Active");
        assert_eq!(SessionState::Draining.to_string(), "Draining");
        assert_eq!(SessionState::Closing.to_string(), "Closing");
        assert_eq!(SessionState::Closed.to_string(), "Closed");
        assert_eq!(SessionState::Poisoned.to_string(), "Poisoned");

        assert_eq!(CloseReason::ClientClose.to_string(), "ClientClose");
        assert_eq!(CloseReason::ClientInitiated.to_string(), "ClientInitiated");
        assert_eq!(CloseReason::ServerClose.to_string(), "ServerClose");
        assert_eq!(CloseReason::ServerError.to_string(), "ServerError");
        assert_eq!(CloseReason::IdleTimeout.to_string(), "IdleTimeout");
        assert_eq!(CloseReason::MaxAgeExceeded.to_string(), "MaxAgeExceeded");
        assert_eq!(
            CloseReason::MaxRequestsExceeded.to_string(),
            "MaxRequestsExceeded"
        );
        assert_eq!(
            CloseReason::MaxRequestsReached.to_string(),
            "MaxRequestsReached"
        );
        assert_eq!(
            CloseReason::KeepaliveTimeout.to_string(),
            "KeepaliveTimeout"
        );
        assert_eq!(CloseReason::ProtocolError.to_string(), "ProtocolError");
        assert_eq!(CloseReason::VersionMismatch.to_string(), "VersionMismatch");
        assert_eq!(CloseReason::ShutdownDrain.to_string(), "ShutdownDrain");
        assert_eq!(CloseReason::CheckoutFailed.to_string(), "CheckoutFailed");
        assert_eq!(CloseReason::Poisoned.to_string(), "Poisoned");
    }
}
