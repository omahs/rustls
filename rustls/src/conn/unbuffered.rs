//! Unbuffered connection API

use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::{fmt, mem};
use std::error::Error as StdError;

use super::UnbufferedConnectionCommon;
use crate::client::ClientConnectionData;
use crate::msgs::deframer::DeframerSliceBuffer;
use crate::server::ServerConnectionData;
use crate::Error;

impl UnbufferedConnectionCommon<ClientConnectionData> {
    /// Processes the TLS records in `incoming_tls` buffer until a new [`UnbufferedStatus`] is
    /// reached.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ClientConnectionData> {
        self.process_tls_records_common(incoming_tls, |_| None::<()>, |_, _, _| unreachable!())
    }
}

impl UnbufferedConnectionCommon<ServerConnectionData> {
    /// Processes the TLS records in `incoming_tls` buffer until a new [`UnbufferedStatus`] is
    /// reached.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ServerConnectionData> {
        self.process_tls_records_common(
            incoming_tls,
            |conn| conn.pop_early_data(),
            |conn, incoming_tls, chunk| EarlyDataAvailable::new(conn, incoming_tls, chunk).into(),
        )
    }
}

impl<Data> UnbufferedConnectionCommon<Data> {
    fn process_tls_records_common<'c, 'i, T>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
        mut check: impl FnMut(&mut Self) -> Option<T>,
        execute: impl FnOnce(&'c mut Self, &'i mut [u8], T) -> ConnectionState<'c, 'i, Data>,
    ) -> UnbufferedStatus<'c, 'i, Data> {
        let mut buffer = DeframerSliceBuffer::new(incoming_tls);

        let (discard, state) = loop {
            if let Some(value) = check(self) {
                break (buffer.pending_discard(), execute(self, incoming_tls, value));
            }

            if let Some(chunk) = self
                .core
                .common_state
                .received_plaintext
                .pop()
            {
                break (
                    buffer.pending_discard(),
                    AppDataAvailable::new(self, incoming_tls, chunk).into(),
                );
            }

            if let Some(chunk) = self
                .core
                .common_state
                .sendable_tls
                .pop()
            {
                break (
                    buffer.pending_discard(),
                    MustEncodeTlsData::new(self, chunk).into(),
                );
            }

            let deframer_output = match self.core.deframe(None, &mut buffer) {
                Err(err) => {
                    return UnbufferedStatus {
                        discard: buffer.pending_discard(),
                        state: Err(err),
                    };
                }
                Ok(r) => r,
            };

            if let Some(msg) = deframer_output {
                let mut state =
                    match mem::replace(&mut self.core.state, Err(Error::HandshakeNotComplete)) {
                        Ok(state) => state,
                        Err(e) => {
                            self.core.state = Err(e.clone());
                            return UnbufferedStatus {
                                discard: buffer.pending_discard(),
                                state: Err(e),
                            };
                        }
                    };

                match self.core.process_msg(msg, state) {
                    Ok(new) => state = new,

                    Err(e) => {
                        self.core.state = Err(e.clone());
                        return UnbufferedStatus {
                            discard: buffer.pending_discard(),
                            state: Err(e),
                        };
                    }
                }

                self.core.state = Ok(state);
            } else if self.wants_write {
                break (
                    buffer.pending_discard(),
                    MustTransmitTlsData { conn: self }.into(),
                );
            } else if self
                .core
                .common_state
                .has_received_close_notify
            {
                break (buffer.pending_discard(), ConnectionState::ConnectionClosed);
            } else if self
                .core
                .common_state
                .may_send_application_data
            {
                break (
                    buffer.pending_discard(),
                    ConnectionState::TrafficTransit(MayEncryptAppData { conn: self }),
                );
            } else {
                break (
                    buffer.pending_discard(),
                    ConnectionState::NeedsMoreTlsData { num_bytes: None },
                );
            }
        };

        UnbufferedStatus {
            discard,
            state: Ok(state),
        }
    }
}

/// The current status of the `UnbufferedConnection*`
#[must_use]
#[derive(Debug)]
pub struct UnbufferedStatus<'c, 'i, Data> {
    /// Number of bytes to discard
    ///
    /// After the `state` field of this object has been handled, `discard` bytes must be
    /// removed from the *front* of the `incoming_tls` buffer that was passed to
    /// the [`UnbufferedConnectionCommon::process_tls_records`] call that returned this object.
    ///
    /// This discard operation MUST happen *before*
    /// [`UnbufferedConnectionCommon::process_tls_records`] is called again.
    pub discard: usize,

    /// The current state of the handshake process
    ///
    /// This value MUST be handled prior to calling
    /// [`UnbufferedConnectionCommon::process_tls_records`] again. See the documentation on the
    /// variants of [`ConnectionState`] for more details.
    pub state: Result<ConnectionState<'c, 'i, Data>, Error>,
}

/// The state of the [`UnbufferedConnectionCommon`] object
#[non_exhaustive] // for forwards compatibility; to support caller-side certificate verification
pub enum ConnectionState<'c, 'i, Data> {
    /// One, or more, application data records are available
    ///
    /// See [`AppDataAvailable`] for more details on how to use the enclosed object to access
    /// the received data.
    AppDataAvailable(AppDataAvailable<'c, 'i, Data>),

    /// Connection has been cleanly closed by the peer
    ConnectionClosed,

    /// One, or more, early (RTT-0) data records are available
    ///
    /// See [`EarlyDataAvailable`] for more details on how to use the enclosed object to access
    /// the received data.
    EarlyDataAvailable(EarlyDataAvailable<'c, 'i, Data>),

    /// A Handshake record is ready for encoding
    ///
    /// Call [`MustEncodeTlsData::encode`] on the enclosed object, providing an `outgoing_tls`
    /// buffer to store the encoding
    MustEncodeTlsData(MustEncodeTlsData<'c, Data>),

    /// Previously encoded handshake records need to be transmitted
    ///
    /// Transmit the contents of the `outgoing_tls` buffer that was passed to previous
    /// [`MustEncodeTlsData::encode`] calls to the peer.
    ///
    /// After transmitting the contents, call [`MustTransmitTlsData::done`] on the enclosed object.
    /// The transmitted contents MUST not be sent to the peer more than once so they SHOULD be
    /// discarded at this point.
    ///
    /// At some stages of the handshake process, it's possible to send application-data alongside
    /// handshake records. Call [`MustTransmitTlsData::may_encrypt_app_data`] on the enclosed
    /// object to probe if that's allowed.
    MustTransmitTlsData(MustTransmitTlsData<'c, Data>),

    /// More TLS data is needed to continue with the handshake
    ///
    /// Request more data from the peer and append the contents to the `incoming_tls` buffer that
    /// was passed to [`UnbufferedConnectionCommon::process_tls_records`].
    NeedsMoreTlsData {
        /// Number of bytes required to complete one TLS record. `None` indicates that
        /// no information is currently available
        num_bytes: Option<NonZeroUsize>,
    },

    /// The handshake process has been completed.
    ///
    /// [`MayEncryptAppData::encrypt`] can be called on the enclosed object to encrypt application
    /// data into an `outgoing_tls` buffer. Similarly, [`MayEncryptAppData::queue_close_notify`] can
    /// be used to encrypt a close_notify alert message into a buffer to signal the peer that the
    /// connection is being closed. Data written into `outgoing_buffer` by either method MAY be
    /// transmitted to the peer during this state.
    ///
    /// Once this state has been reached, data MAY be requested from the peer and appended to an
    /// `incoming_tls` buffer that will be passed to a future
    /// [`UnbufferedConnectionCommon::process_tls_records`] invocation. When enough data has been
    /// appended to `incoming_tls`, [`UnbufferedConnectionCommon::process_tls_records`] will yield
    /// the [`ConnectionState::AppDataAvailable`] state.
    TrafficTransit(MayEncryptAppData<'c, Data>),
}

impl<'c, 'i, Data> From<AppDataAvailable<'c, 'i, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: AppDataAvailable<'c, 'i, Data>) -> Self {
        Self::AppDataAvailable(v)
    }
}

impl<'c, 'i, Data> From<EarlyDataAvailable<'c, 'i, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: EarlyDataAvailable<'c, 'i, Data>) -> Self {
        Self::EarlyDataAvailable(v)
    }
}

impl<'c, 'i, Data> From<MustEncodeTlsData<'c, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: MustEncodeTlsData<'c, Data>) -> Self {
        Self::MustEncodeTlsData(v)
    }
}

impl<'c, 'i, Data> From<MustTransmitTlsData<'c, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: MustTransmitTlsData<'c, Data>) -> Self {
        Self::MustTransmitTlsData(v)
    }
}

impl<Data> fmt::Debug for ConnectionState<'_, '_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppDataAvailable(..) => f
                .debug_tuple("AppDataAvailable")
                .finish(),

            Self::ConnectionClosed => write!(f, "ConnectionClosed"),

            Self::EarlyDataAvailable(..) => f
                .debug_tuple("EarlyDataAvailable")
                .finish(),

            Self::MustEncodeTlsData(..) => f
                .debug_tuple("MustEncodeTlsData")
                .finish(),

            Self::MustTransmitTlsData(..) => f
                .debug_tuple("MustTransmitTlsData")
                .finish(),

            Self::NeedsMoreTlsData { num_bytes } => f
                .debug_struct("NeedsMoreTlsData")
                .field("num_bytes", num_bytes)
                .finish(),

            Self::TrafficTransit(..) => f.debug_tuple("TrafficTransit").finish(),
        }
    }
}

/// Application data is available
pub struct AppDataAvailable<'c, 'i, Data> {
    _conn: &'c mut UnbufferedConnectionCommon<Data>,
    // for forwards compatibility; to support in-place decryption in the future
    _incoming_tls: &'i mut [u8],
    chunk: Vec<u8>,
    taken: bool,
}

impl<'c, 'i, Data> AppDataAvailable<'c, 'i, Data> {
    fn new(
        _conn: &'c mut UnbufferedConnectionCommon<Data>,
        _incoming_tls: &'i mut [u8],
        chunk: Vec<u8>,
    ) -> Self {
        Self {
            _conn,
            _incoming_tls,
            chunk,
            taken: false,
        }
    }

    /// Decrypts and returns the next available app-data record
    // TODO deprecate in favor of `Iterator` implementation, which requires in-place decryption
    pub fn next_record(&mut self) -> Option<Result<AppDataRecord, Error>> {
        if self.taken {
            None
        } else {
            self.taken = true;
            Some(Ok(AppDataRecord {
                discard: 0,
                payload: &self.chunk,
            }))
        }
    }

    /// Returns the payload size of the next app-data record *without* decrypting it
    ///
    /// Returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        if self.taken {
            None
        } else {
            NonZeroUsize::new(self.chunk.len())
        }
    }
}

/// Early application-data is available.
pub struct EarlyDataAvailable<'c, 'i, Data> {
    _conn: &'c mut UnbufferedConnectionCommon<Data>,
    // for forwards compatibility; to support in-place decryption in the future
    _incoming_tls: &'i mut [u8],
    chunk: Vec<u8>,
    taken: bool,
}

impl<'c, 'i, Data> EarlyDataAvailable<'c, 'i, Data> {
    fn new(
        _conn: &'c mut UnbufferedConnectionCommon<Data>,
        _incoming_tls: &'i mut [u8],
        chunk: Vec<u8>,
    ) -> Self {
        Self {
            _conn,
            _incoming_tls,
            chunk,
            taken: false,
        }
    }
}

impl<'c, 'i> EarlyDataAvailable<'c, 'i, ServerConnectionData> {
    /// decrypts and returns the next available app-data record
    // TODO deprecate in favor of `Iterator` implementation, which requires in-place decryption
    pub fn next_record(&mut self) -> Option<Result<AppDataRecord, Error>> {
        if self.taken {
            None
        } else {
            self.taken = true;
            Some(Ok(AppDataRecord {
                discard: 0,
                payload: &self.chunk,
            }))
        }
    }

    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        if self.taken {
            None
        } else {
            NonZeroUsize::new(self.chunk.len())
        }
    }
}

/// A decrypted application-data record
pub struct AppDataRecord<'i> {
    /// Number of additional bytes to discard
    ///
    /// This number MUST be added to the value of [`UnbufferedStatus.discard`] *prior* to the
    /// discard operation. See [`UnbufferedStatus.discard`] for more details
    pub discard: usize,

    /// The payload of the app-data record
    pub payload: &'i [u8],
}

/// Allows encrypting app-data
pub struct MayEncryptAppData<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> MayEncryptAppData<'_, Data> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .core
            .common_state
            .eager_send_some_plaintext(application_data, outgoing_tls)
    }

    /// Encrypts a close_notify warning alert in `outgoing_tls`
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn queue_close_notify(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn
            .core
            .common_state
            .eager_send_close_notify(outgoing_tls)
    }
}

/// A handshake record must be encoded
pub struct MustEncodeTlsData<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
    chunk: Option<Vec<u8>>,
}

impl<'c, Data> MustEncodeTlsData<'c, Data> {
    fn new(conn: &'c mut UnbufferedConnectionCommon<Data>, chunk: Vec<u8>) -> Self {
        Self {
            conn,
            chunk: Some(chunk),
        }
    }

    /// Encodes a handshake record into the `outgoing_tls` buffer
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn encode(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncodeError> {
        let chunk = match self.chunk.take() {
            Some(chunk) => chunk,
            None => return Err(EncodeError::AlreadyEncoded),
        };

        let required_size = chunk.len();

        if required_size > outgoing_tls.len() {
            self.chunk = Some(chunk);
            Err(InsufficientSizeError { required_size }.into())
        } else {
            let written = chunk.len();
            outgoing_tls[..written].copy_from_slice(&chunk);

            self.conn.wants_write = true;

            Ok(written)
        }
    }
}

/// Previously encoded TLS data must be transmitted
pub struct MustTransmitTlsData<'c, Data> {
    pub(crate) conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> MustTransmitTlsData<'_, Data> {
    /// Signals that the previously encoded TLS data has been transmitted
    pub fn done(self) {
        self.conn.wants_write = false;
    }

    /// Returns an adapter that allows encrypting application data
    ///
    /// If allowed at this stage of the handshake process
    pub fn may_encrypt_app_data(&mut self) -> Option<MayEncryptAppData<Data>> {
        if self
            .conn
            .core
            .common_state
            .may_send_application_data
        {
            Some(MayEncryptAppData { conn: self.conn })
        } else {
            None
        }
    }
}

/// Errors that may arise when encoding a handshake record
#[derive(Debug)]
pub enum EncodeError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encoded; do not call `encode` again
    AlreadyEncoded,
}

impl From<InsufficientSizeError> for EncodeError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encode due to insufficient size, {} bytes are required",
                required_size
            ),
            Self::AlreadyEncoded => "cannot encode, data has already been encoded".fmt(f),
        }
    }
}

impl StdError for EncodeError {}

/// Errors that may arise when encrypting application data
#[derive(Debug)]
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// Encrypter has been exhausted
    EncryptExhausted,
}

impl From<InsufficientSizeError> for EncryptError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encrypt due to insufficient size, {required_size} bytes are required"
            ),
            Self::EncryptExhausted => f.write_str("encrypter has been exhausted"),
        }
    }
}

impl StdError for EncryptError {}

/// Provided buffer was too small
#[derive(Clone, Copy, Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}
