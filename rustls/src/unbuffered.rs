//! Unbuffered connection API
//!
//! This is an alternative to the [`crate::ConnectionCommon`] API that does not internally buffer
//! TLS nor plaintext data. Instead those buffers are managed by the API user so they have
//! control over when and how to allocate, resize and dispose of them.
//!
//! This API is lower level than the `ConnectionCommon` API and is built around a state machine
//! interface where the API user must handle each state to advance and complete the
//! handshake process.
//!
//! Like the `ConnectionCommon` API, no IO happens internally so all IO must be handled by the API
//! user. Unlike the `ConnectionCommon` API, this API does not make use of the [`std::io::Read`] and
//! [`std::io::Write`] traits so it's usable in no-std context.
//!
//! The entry points into this API are [`crate::client::UnbufferedClientConnection::new`],
//! [`crate::server::UnbufferedServerConnection::new`] and
//! [`UnbufferedConnectionCommon::process_tls_records`]. The state machine API is documented in
//! [`ConnectionState`].
//!
//! # Examples
//!
//! [`unbuffered-client`] and [`unbuffered-server`] are examples that fully exercise the API in
//! std, non-async context.
//!
//! [`unbuffered-client`]: https://github.com/rustls/rustls/blob/main/examples/src/bin/unbuffererd-client.rs
//! [`unbuffered-server`]: https://github.com/rustls/rustls/blob/main/examples/src/bin/unbuffererd-server.rs

pub use crate::conn::unbuffered::{
    AppDataAvailable, AppDataRecord, ConnectionState, EarlyDataAvailable, EncodeError,
    EncryptError, InsufficientSizeError, MayEncryptAppData, MustEncodeTlsData, MustTransmitTlsData,
    UnbufferedStatus,
};
pub use crate::conn::UnbufferedConnectionCommon;
