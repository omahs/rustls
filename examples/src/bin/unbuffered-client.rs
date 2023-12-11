use std::error::Error;
use std::net::TcpStream;
use std::sync::Arc;

use helpers::KB;
use rustls::client::{ClientConnectionData, EarlyDataError, UnbufferedClientConnection};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, MayEncryptAppData, UnbufferedStatus,
};
#[allow(unused_imports)]
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use rustls_examples as helpers;

const SERVER_NAME: &str = "example.com";
const PORT: u16 = 443;

const INCOMING_TLS_BUFSIZE: usize = 16 * KB;
const OUTGOING_TLS_INITIAL_BUFSIZE: usize = KB;

const MAX_ITERATIONS: usize = 20;
const SEND_EARLY_DATA: bool = false;
const EARLY_DATA: &[u8] = b"hello";

fn main() -> Result<(), Box<dyn Error>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_early_data = SEND_EARLY_DATA;

    let config = Arc::new(config);

    let mut incoming_tls = [0; INCOMING_TLS_BUFSIZE];
    let mut outgoing_tls = vec![0; OUTGOING_TLS_INITIAL_BUFSIZE];

    converse(&config, false, &mut incoming_tls, &mut outgoing_tls)?;
    if SEND_EARLY_DATA {
        eprintln!("---- second connection ----");
        converse(&config, true, &mut incoming_tls, &mut outgoing_tls)?;
    }

    Ok(())
}

fn converse(
    config: &Arc<ClientConfig>,
    send_early_data: bool,
    incoming_tls: &mut [u8],
    outgoing_tls: &mut Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut conn = UnbufferedClientConnection::new(Arc::clone(config), SERVER_NAME.try_into()?)?;
    let mut sock = TcpStream::connect(format!("{SERVER_NAME}:{PORT}"))?;

    let mut incoming_used = 0;
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut sent_request = false;
    let mut received_response = false;
    let mut sent_early_data = false;

    let mut iter_count = 0;
    while open_connection {
        let UnbufferedStatus { mut discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used]);

        match dbg!(state.unwrap()) {
            ConnectionState::AppDataAvailable(mut state) => {
                while let Some(res) = state.next_record() {
                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                    } = res?;
                    discard += new_discard;

                    if payload.starts_with(b"HTTP") {
                        let response = core::str::from_utf8(payload)?;
                        let header = response
                            .lines()
                            .next()
                            .unwrap_or(response);

                        println!("{header}");
                    } else {
                        println!("(.. continued HTTP response ..)");
                    }

                    received_response = true;
                }
            }

            ConnectionState::MustEncodeTlsData(mut state) => {
                helpers::try_or_resize_and_retry(
                    |out_buffer| state.encode(out_buffer),
                    |e| {
                        if let EncodeError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    outgoing_tls,
                    &mut outgoing_used,
                )?;
            }

            ConnectionState::MustTransmitTlsData(mut state) => {
                if let Some(mut may_encrypt_early_data) = state.may_encrypt_early_data() {
                    let written = helpers::try_or_resize_and_retry(
                        |out_buffer| may_encrypt_early_data.encrypt(EARLY_DATA, out_buffer),
                        |e| {
                            if let EarlyDataError::Encrypt(EncryptError::InsufficientSize(is)) = &e
                            {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                        outgoing_tls,
                        &mut outgoing_used,
                    )?;

                    eprintln!("queued {written}B of early data");
                    sent_early_data = true;
                }

                if let Some(mut may_encrypt) = state.may_encrypt_app_data() {
                    encrypt_http_request(
                        &mut sent_request,
                        &mut may_encrypt,
                        outgoing_tls,
                        &mut outgoing_used,
                    );
                }

                helpers::send_tls(&mut sock, outgoing_tls, &mut outgoing_used)?;
                state.done();
            }

            ConnectionState::NeedsMoreTlsData { .. } => {
                helpers::recv_tls(&mut sock, incoming_tls, &mut incoming_used)?;
            }

            ConnectionState::TrafficTransit(mut may_encrypt) => {
                if encrypt_http_request(
                    &mut sent_request,
                    &mut may_encrypt,
                    outgoing_tls,
                    &mut outgoing_used,
                ) {
                    helpers::send_tls(&mut sock, outgoing_tls, &mut outgoing_used)?;
                    helpers::recv_tls(&mut sock, incoming_tls, &mut incoming_used)?;
                } else if !received_response {
                    // this happens in the TLS 1.3 case. the app-data was sent in the preceding
                    // `MustTransmitTlsData` state. the server should have already written a
                    // response which we can read out from the socket
                    helpers::recv_tls(&mut sock, incoming_tls, &mut incoming_used)?;
                } else {
                    helpers::try_or_resize_and_retry(
                        |out_buffer| may_encrypt.queue_close_notify(out_buffer),
                        |e| {
                            if let EncryptError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                        outgoing_tls,
                        &mut outgoing_used,
                    )?;
                    helpers::send_tls(&mut sock, outgoing_tls, &mut outgoing_used)?;
                    open_connection = false;
                }
            }

            ConnectionState::ConnectionClosed => {
                open_connection = false;
            }

            // other states are not expected in this example
            _ => unreachable!(),
        }

        if discard != 0 {
            assert!(discard <= incoming_used);

            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;

            eprintln!("discarded {discard}B from `incoming_tls`");
        }

        iter_count += 1;
        assert!(
            iter_count < MAX_ITERATIONS,
            "did not get a HTTP response within {MAX_ITERATIONS} iterations"
        );
    }

    assert!(sent_request);
    assert!(received_response);
    assert_eq!(send_early_data, sent_early_data);
    assert_eq!(0, incoming_used);
    assert_eq!(0, outgoing_used);

    Ok(())
}

fn encrypt_http_request(
    sent_request: &mut bool,
    may_encrypt: &mut MayEncryptAppData<'_, ClientConnectionData>,
    outgoing_tls: &mut [u8],
    outgoing_used: &mut usize,
) -> bool {
    if !*sent_request {
        let request = format!("GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").into_bytes();
        let written = may_encrypt
            .encrypt(&request, &mut outgoing_tls[*outgoing_used..])
            .expect("encrypted request does not fit in `outgoing_tls`");
        *outgoing_used += written;
        *sent_request = true;
        eprintln!("queued HTTP request");
        true
    } else {
        false
    }
}
