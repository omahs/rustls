#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use std::sync::Arc;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    ConnectionState, MayEncryptAppData, UnbufferedConnectionCommon, UnbufferedStatus,
};
use rustls::version::TLS13;

use crate::common::*;

mod common;

const MAX_ITERATIONS: usize = 100;

#[test]
fn handshake() {
    for version in rustls::ALL_VERSIONS {
        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.client_send(),
                State::NeedsMoreTlsData => buffers.server_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => client_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.server_send(),
                State::NeedsMoreTlsData => buffers.client_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }
    }
}

#[test]
fn app_data_client_to_server() {
    let expected: &[_] = b"hello";
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");

        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut client_actions = Actions {
            app_data_to_send: Some(expected),
            ..NO_ACTIONS
        };
        let mut received_app_data = vec![];
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, client_actions) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => {
                    buffers.client_send();

                    if sent_app_data {
                        client_actions.app_data_to_send = None;
                    }
                }
                State::NeedsMoreTlsData => buffers.server_send(),
                State::TrafficTransit {
                    sent_app_data,
                    sent_close_notify: false,
                } => {
                    if sent_app_data {
                        buffers.client_send();
                        client_actions.app_data_to_send = None;
                    }

                    client_handshake_done = true
                }
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.server_send(),
                State::NeedsMoreTlsData => buffers.client_send(),
                State::ReceivedAppData { records } => {
                    received_app_data.extend(records);
                }
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }

        assert!(client_actions
            .app_data_to_send
            .is_none());
        assert_eq!([expected], received_app_data.as_slice());
    }
}

#[test]
fn app_data_server_to_client() {
    let expected: &[_] = b"hello";
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");

        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut server_actions = Actions {
            app_data_to_send: Some(expected),
            ..NO_ACTIONS
        };
        let mut received_app_data = vec![];
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.client_send(),
                State::NeedsMoreTlsData => buffers.server_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => client_handshake_done = true,
                State::ReceivedAppData { records } => {
                    received_app_data.extend(records);
                }
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, server_actions) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => {
                    buffers.server_send();
                    if sent_app_data {
                        server_actions.app_data_to_send = None;
                    }
                }
                State::NeedsMoreTlsData => buffers.client_send(),
                State::ReceivedAppData { records } => {
                    received_app_data.extend(records);
                }
                // server does not need to reach this state to send data to the client
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }

        assert!(server_actions
            .app_data_to_send
            .is_none());
        assert_eq!([expected], received_app_data.as_slice());
    }
}

#[test]
fn early_data() {
    let expected: &[_] = b"hello";

    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.max_early_data_size = 128;
    let server_config = Arc::new(server_config);

    let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[&TLS13]);
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);

    for conn_count in 0..2 {
        eprintln!("----");
        let mut client =
            UnbufferedClientConnection::new(client_config.clone(), server_name("localhost"))
                .unwrap();
        let mut server = UnbufferedServerConnection::new(server_config.clone()).unwrap();
        let mut buffers = BothBuffers::default();

        let mut client_actions = Actions {
            early_data_to_send: Some(expected),
            ..NO_ACTIONS
        };
        let mut received_early_data = vec![];
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, client_actions) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data,
                } => {
                    buffers.client_send();

                    if sent_early_data {
                        client_actions.early_data_to_send = None;
                    }
                }
                State::NeedsMoreTlsData => buffers.server_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => client_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.server_send(),
                State::NeedsMoreTlsData => buffers.client_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => server_handshake_done = true,
                State::ReceivedEarlyData { records } => {
                    received_early_data.extend(records);
                }
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(count <= MAX_ITERATIONS, "handshake was not completed");
        }

        // early data is not exchanged on the first server interaction
        if conn_count == 1 {
            assert!(client_actions
                .early_data_to_send
                .is_none());
            assert_eq!([expected], received_early_data.as_slice());
        }
    }
}

#[test]
fn close_notify_client_to_server() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");

        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut client_actions = Actions {
            send_close_notify: true,
            ..NO_ACTIONS
        };
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        let mut reached_connection_closed_state = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, client_actions) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify,
                    sent_early_data: false,
                } => {
                    buffers.client_send();
                    if sent_close_notify {
                        client_actions.send_close_notify = false;
                    }
                }
                State::NeedsMoreTlsData => buffers.server_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify,
                } => {
                    if sent_close_notify {
                        buffers.client_send();
                        client_actions.send_close_notify = false;
                    }
                    client_handshake_done = true;
                }
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.server_send(),
                State::NeedsMoreTlsData => buffers.client_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => server_handshake_done = true,
                State::ConnectionClosed => {
                    server_handshake_done = true;
                    reached_connection_closed_state = true
                }
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }

        assert!(!client_actions.send_close_notify);
        assert!(reached_connection_closed_state);
    }
}

#[test]
fn close_notify_server_to_client() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");

        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut server_actions = Actions {
            send_close_notify: true,
            ..NO_ACTIONS
        };
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        let mut reached_connection_closed_state = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify: false,
                    sent_early_data: false,
                } => buffers.client_send(),
                State::NeedsMoreTlsData => buffers.server_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    sent_close_notify: false,
                } => client_handshake_done = true,
                State::ConnectionClosed => {
                    client_handshake_done = true;
                    reached_connection_closed_state = true
                }
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, server_actions) {
                State::EncodedTlsData => {}
                State::MustTransmitTlsData {
                    sent_app_data: false,
                    sent_close_notify,
                    sent_early_data: false,
                } => {
                    buffers.server_send();
                    if sent_close_notify {
                        server_actions.send_close_notify = false;
                    }
                }
                State::NeedsMoreTlsData => buffers.client_send(),
                State::TrafficTransit {
                    sent_app_data: false,
                    // servers don't need to reach this state to send a close_notify alert
                    sent_close_notify: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }

        assert!(!server_actions.send_close_notify);
        assert!(reached_connection_closed_state);
    }
}

#[derive(Debug)]
enum State {
    ConnectionClosed,
    EncodedTlsData,
    MustTransmitTlsData {
        sent_app_data: bool,
        sent_close_notify: bool,
        sent_early_data: bool,
    },
    NeedsMoreTlsData,
    ReceivedAppData {
        records: Vec<Vec<u8>>,
    },
    ReceivedEarlyData {
        records: Vec<Vec<u8>>,
    },
    TrafficTransit {
        sent_app_data: bool,
        sent_close_notify: bool,
    },
}

const NO_ACTIONS: Actions = Actions {
    app_data_to_send: None,
    early_data_to_send: None,
    send_close_notify: false,
};

#[derive(Clone, Copy, Debug)]
struct Actions<'a> {
    app_data_to_send: Option<&'a [u8]>,
    early_data_to_send: Option<&'a [u8]>,
    send_close_notify: bool,
}

fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
) -> State {
    let UnbufferedStatus { discard, state } = conn
        .process_tls_records(buffers.incoming.filled())
        .unwrap();

    let state = match state {
        ConnectionState::MustTransmitTlsData(mut state) => {
            let mut sent_early_data = false;
            if let Some(early_data) = actions.early_data_to_send {
                if let Some(mut state) = state.may_encrypt_early_data() {
                    let written = state
                        .encrypt(early_data, buffers.outgoing.unfilled())
                        .unwrap();
                    buffers.outgoing.advance(written);
                    sent_early_data = true;
                }
            }
            state.done();
            State::MustTransmitTlsData {
                sent_app_data: false,
                sent_close_notify: false,
                sent_early_data,
            }
        }

        state => handle_state(state, &mut buffers.outgoing, actions),
    };
    buffers.incoming.discard(discard);

    state
}

fn advance_server(
    conn: &mut UnbufferedConnectionCommon<ServerConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
) -> State {
    let UnbufferedStatus { discard, state } = conn
        .process_tls_records(buffers.incoming.filled())
        .unwrap();

    let state = match state {
        ConnectionState::EarlyDataAvailable(mut state) => {
            let mut records = vec![];

            while let Some(res) = state.next_record() {
                records.push(res.unwrap().payload.to_vec());
            }

            State::ReceivedEarlyData { records }
        }

        state => handle_state(state, &mut buffers.outgoing, actions),
    };
    buffers.incoming.discard(discard);

    state
}

fn handle_state<Data>(
    state: ConnectionState<'_, '_, Data>,
    outgoing: &mut Buffer,
    actions: Actions,
) -> State {
    match state {
        ConnectionState::MustEncodeTlsData(mut state) => {
            let written = state
                .encode(outgoing.unfilled())
                .unwrap();
            outgoing.advance(written);

            State::EncodedTlsData
        }

        ConnectionState::MustTransmitTlsData(mut state) => {
            let mut sent_app_data = false;
            if let Some(app_data) = actions.app_data_to_send {
                if let Some(mut state) = state.may_encrypt_app_data() {
                    encrypt(&mut state, app_data, outgoing);
                    sent_app_data = true;
                }
            }

            let mut sent_close_notify = false;
            if let Some(mut state) = state.may_encrypt_app_data() {
                if actions.send_close_notify {
                    queue_close_notify(&mut state, outgoing);
                    sent_close_notify = true;
                }
            }

            // this should be called *after* the data has been transmitted but it's easier to
            // do it in reverse
            state.done();
            State::MustTransmitTlsData {
                sent_app_data,
                sent_early_data: false,
                sent_close_notify,
            }
        }

        ConnectionState::NeedsMoreTlsData { .. } => State::NeedsMoreTlsData,

        ConnectionState::TrafficTransit(mut state) => {
            let mut sent_app_data = false;
            if let Some(app_data) = actions.app_data_to_send {
                encrypt(&mut state, app_data, outgoing);
                sent_app_data = true;
            }

            let mut sent_close_notify = false;
            if actions.send_close_notify {
                queue_close_notify(&mut state, outgoing);
                sent_close_notify = true;
            }

            State::TrafficTransit {
                sent_app_data,
                sent_close_notify,
            }
        }

        ConnectionState::AppDataAvailable(mut state) => {
            let mut records = vec![];

            while let Some(res) = state.next_record() {
                records.push(res.unwrap().payload.to_vec());
            }

            State::ReceivedAppData { records }
        }

        ConnectionState::ConnectionClosed => State::ConnectionClosed,

        _ => unreachable!(),
    }
}

fn queue_close_notify<Data>(state: &mut MayEncryptAppData<'_, Data>, outgoing: &mut Buffer) {
    let written = state
        .queue_close_notify(outgoing.unfilled())
        .unwrap();
    outgoing.advance(written);
}

fn encrypt<Data>(state: &mut MayEncryptAppData<'_, Data>, app_data: &[u8], outgoing: &mut Buffer) {
    let written = state
        .encrypt(app_data, outgoing.unfilled())
        .unwrap();
    outgoing.advance(written);
}

#[derive(Default)]
struct BothBuffers {
    client: Buffers,
    server: Buffers,
}

impl BothBuffers {
    fn client_send(&mut self) {
        let client_data = self.client.outgoing.filled();
        let num_bytes = client_data.len();
        if num_bytes == 0 {
            return;
        }
        self.server.incoming.append(client_data);
        self.client.outgoing.clear();
        eprintln!("client sent {num_bytes}B");
    }

    fn server_send(&mut self) {
        let server_data = self.server.outgoing.filled();
        let num_bytes = server_data.len();
        if num_bytes == 0 {
            return;
        }
        self.client.incoming.append(server_data);
        self.server.outgoing.clear();
        eprintln!("server sent {num_bytes}B");
    }
}

#[derive(Default)]
struct Buffers {
    incoming: Buffer,
    outgoing: Buffer,
}

struct Buffer {
    inner: Vec<u8>,
    used: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            inner: vec![0; 16 * 1024],
            used: 0,
        }
    }
}

impl Buffer {
    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn append(&mut self, bytes: &[u8]) {
        let num_bytes = bytes.len();
        self.unfilled()[..num_bytes].copy_from_slice(bytes);
        self.advance(num_bytes)
    }

    fn clear(&mut self) {
        self.used = 0;
    }

    fn discard(&mut self, discard: usize) {
        if discard != 0 {
            assert!(discard <= self.used);

            self.inner
                .copy_within(discard..self.used, 0);
            self.used -= discard;
        }
    }

    fn filled(&mut self) -> &mut [u8] {
        &mut self.inner[..self.used]
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.inner[self.used..]
    }
}

fn make_connection_pair(
    version: &'static rustls::SupportedProtocolVersion,
) -> (UnbufferedClientConnection, UnbufferedServerConnection) {
    let server_config = make_server_config(KeyType::Rsa);
    let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);

    let client =
        UnbufferedClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
    let server = UnbufferedServerConnection::new(Arc::new(server_config)).unwrap();
    (client, server)
}
