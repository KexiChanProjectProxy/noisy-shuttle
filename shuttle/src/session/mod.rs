//! Session management module for reusable connections.
//!
//! This module provides lifecycle states, close reasons, and observability
//! events for connection pooling. Feature activation is independent.

pub mod frame;
pub mod keepalive;
pub mod lifecycle;
pub mod negotiate;
