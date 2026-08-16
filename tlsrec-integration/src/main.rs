use std::env;
use std::io::{BufRead, Cursor, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::client::UnbufferedClientConnection;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, UnbufferedStatus};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    SupportedCipherSuite,
};

const SERVER_CERT: &[u8] = include_bytes!("../../test-ca/rsa-2048/end.fullchain");
const SERVER_KEY: &[u8] = include_bytes!("../../test-ca/rsa-2048/end.key");
const CA_CERT: &[u8] = include_bytes!("../../test-ca/rsa-2048/ca.der");
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_RECEIVE_LIMIT: usize = 512;
const SERVER_RECEIVE_LIMIT: usize = 256;

#[derive(Clone, Copy)]
struct SuiteCase {
    rustls: SupportedCipherSuite,
    openssl: &'static str,
}

fn suite_cases() -> [SuiteCase; 3] {
    [
        SuiteCase {
            rustls: aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            openssl: "TLS_AES_128_GCM_SHA256",
        },
        SuiteCase {
            rustls: aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            openssl: "TLS_AES_256_GCM_SHA384",
        },
        SuiteCase {
            rustls: aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            openssl: "TLS_CHACHA20_POLY1305_SHA256",
        },
    ]
}

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    match args.next() {
        None => run_in_memory_matrix(),
        Some(mode) if mode == "openssl-interop" => {
            let openssl = args
                .next()
                .map(PathBuf::from)
                .expect("openssl-interop requires an absolute OpenSSL binary path");
            assert!(args.next().is_none(), "unexpected extra argument");
            assert!(openssl.is_absolute(), "OpenSSL path must be absolute");
            run_openssl_matrix(&openssl);
        }
        Some(mode) => panic!("unknown mode: {}", mode.to_string_lossy()),
    }
}

fn run_in_memory_matrix() {
    for case in suite_cases() {
        run_in_memory_suite(case.rustls);
        println!("tlsrec in-memory integration passed: {}", case.openssl);
    }
}

fn provider_for_suite(suite: SupportedCipherSuite) -> rustls::crypto::CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider
        .cipher_suites
        .retain(|candidate| candidate.suite() == suite.suite());
    assert_eq!(provider.cipher_suites.len(), 1);
    provider
}

fn server_config_for_suite(suite: SupportedCipherSuite) -> Arc<ServerConfig> {
    server_config_with_limit(suite, Some(SERVER_RECEIVE_LIMIT))
}

fn server_config_with_limit(
    suite: SupportedCipherSuite,
    receive_limit: Option<usize>,
) -> Arc<ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(SERVER_CERT)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider_for_suite(suite)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.record_size_limit =
        receive_limit.map(|limit| rustls::RecordSizeLimit::new(limit).unwrap());
    Arc::new(config)
}

fn client_config_for_suite(suite: SupportedCipherSuite) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_CERT))
        .unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider_for_suite(suite)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.record_size_limit = Some(rustls::RecordSizeLimit::new(CLIENT_RECEIVE_LIMIT).unwrap());
    Arc::new(config)
}

fn run_in_memory_suite(suite: SupportedCipherSuite) {
    let mut client = ClientConnection::new(
        client_config_for_suite(suite),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config_for_suite(suite)).unwrap();

    while client.is_handshaking() || server.is_handshaking() {
        client_to_server(&mut client, &mut server);
        server_to_client(&mut server, &mut client);
    }

    client
        .writer()
        .write_all(b"first epoch")
        .unwrap();
    client_to_server(&mut client, &mut server);
    let mut received = [0u8; 11];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"first epoch");

    client.refresh_traffic_keys().unwrap();
    client
        .writer()
        .write_all(b"next epoch")
        .unwrap();
    client_to_server(&mut client, &mut server);
    server_to_client(&mut server, &mut client);
    client_to_server(&mut client, &mut server);
    let mut received = [0u8; 10];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"next epoch");

    server.refresh_traffic_keys().unwrap();
    server
        .writer()
        .write_all(b"server epoch")
        .unwrap();
    server_to_client(&mut server, &mut client);
    client_to_server(&mut client, &mut server);
    server_to_client(&mut server, &mut client);
    let mut received = [0u8; 12];
    client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"server epoch");

    client.refresh_traffic_keys().unwrap();
    server.refresh_traffic_keys().unwrap();
    client
        .writer()
        .write_all(b"cross client")
        .unwrap();
    server
        .writer()
        .write_all(b"cross server")
        .unwrap();
    client_to_server(&mut client, &mut server);
    server_to_client(&mut server, &mut client);
    client_to_server(&mut client, &mut server);
    server_to_client(&mut server, &mut client);
    let mut received = [0u8; 12];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"cross client");
    let mut received = [0u8; 12];
    client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"cross server");

    let client_bulk = vec![0x5a; 4 * SERVER_RECEIVE_LIMIT];
    client
        .writer()
        .write_all(&client_bulk)
        .unwrap();
    client_to_server(&mut client, &mut server);
    let mut received = vec![0; client_bulk.len()];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(received, client_bulk);

    let server_bulk = vec![0xa5; 4 * CLIENT_RECEIVE_LIMIT];
    server
        .writer()
        .write_all(&server_bulk)
        .unwrap();
    server_to_client(&mut server, &mut client);
    let mut received = vec![0; server_bulk.len()];
    client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(received, server_bulk);

    client.send_close_notify();
    client_to_server(&mut client, &mut server);
    assert!(
        server
            .process_new_packets()
            .unwrap()
            .peer_has_closed()
    );
    server.send_close_notify();
    server_to_client(&mut server, &mut client);
    assert!(
        client
            .process_new_packets()
            .unwrap()
            .peer_has_closed()
    );

    reject_old_epoch_replay(suite);
    accept_unnegotiated_record_size_limit(suite);
    fragmented_encrypted_extensions_at_minimum_limit(suite);
    run_unbuffered_suite(suite);
    key_update_response_precedes_unsealed_application(suite);
    key_update_finishes_committed_record_before_response(suite);
    key_update_after_local_close_is_read_only(suite);
}

fn connected_pair(suite: SupportedCipherSuite) -> (ClientConnection, ServerConnection) {
    let mut client = ClientConnection::new(
        client_config_for_suite(suite),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config_for_suite(suite)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        client_to_server(&mut client, &mut server);
        server_to_client(&mut server, &mut client);
    }
    (client, server)
}

fn key_update_response_precedes_unsealed_application(suite: SupportedCipherSuite) {
    let (mut client, mut server) = connected_pair(suite);
    server
        .writer()
        .write_all(b"queued application")
        .unwrap();
    client.refresh_traffic_keys().unwrap();
    client_to_server(&mut client, &mut server);

    let response = take_one_server_write(&mut server);
    assert_eq!(tls_record_count(&response), 1);
    feed_client_tls(&response, &mut client).unwrap();
    assert_no_plaintext(&mut client);

    let application = take_one_server_write(&mut server);
    assert_eq!(tls_record_count(&application), 1);
    feed_client_tls(&application, &mut client).unwrap();
    let mut received = [0u8; 18];
    client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"queued application");
}

fn key_update_finishes_committed_record_before_response(suite: SupportedCipherSuite) {
    let (mut client, mut server) = connected_pair(suite);
    server
        .writer()
        .write_all(b"record A")
        .unwrap();
    server
        .writer()
        .write_all(b"record B")
        .unwrap();

    let mut prefix = PrefixWriter::new(3);
    assert_eq!(server.write_tls(&mut prefix).unwrap(), 3);
    assert_eq!(prefix.bytes.len(), 3);

    client.refresh_traffic_keys().unwrap();
    client_to_server(&mut client, &mut server);

    let remainder_a = take_one_server_write(&mut server);
    let mut record_a = prefix.bytes;
    record_a.extend_from_slice(&remainder_a);
    assert_eq!(tls_record_count(&record_a), 1);
    feed_client_tls(&record_a, &mut client).unwrap();
    let mut received_a = [0u8; 8];
    client
        .reader()
        .read_exact(&mut received_a)
        .unwrap();
    assert_eq!(&received_a, b"record A");

    let response = take_one_server_write(&mut server);
    assert_eq!(tls_record_count(&response), 1);
    feed_client_tls(&response, &mut client).unwrap();
    assert_no_plaintext(&mut client);

    let record_b = take_one_server_write(&mut server);
    assert_eq!(tls_record_count(&record_b), 1);
    feed_client_tls(&record_b, &mut client).unwrap();
    let mut received_b = [0u8; 8];
    client
        .reader()
        .read_exact(&mut received_b)
        .unwrap();
    assert_eq!(&received_b, b"record B");
}

fn key_update_after_local_close_is_read_only(suite: SupportedCipherSuite) {
    let (mut client, mut server) = connected_pair(suite);
    server.send_close_notify();
    client.refresh_traffic_keys().unwrap();
    let update = take_client_tls(&mut client);
    assert_single_protected_record(&update, "KeyUpdate after peer local close");
    assert_protected_record_limit(&update, SERVER_RECEIVE_LIMIT);
    feed_server_tls(&update, &mut server).unwrap();

    let close = take_one_server_write(&mut server);
    assert_single_protected_record(&close, "local close_notify");
    feed_client_tls(&close, &mut client).unwrap();
    assert!(
        client
            .process_new_packets()
            .unwrap()
            .peer_has_closed()
    );
    assert!(!server.wants_write());

    client
        .writer()
        .write_all(b"read side remains open")
        .unwrap();
    client_to_server(&mut client, &mut server);
    let mut received = [0u8; 22];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"read side remains open");

    client.refresh_traffic_keys().unwrap();
    let second_update = take_client_tls(&mut client);
    assert_single_protected_record(&second_update, "second KeyUpdate after peer local close");
    assert_protected_record_limit(&second_update, SERVER_RECEIVE_LIMIT);
    feed_server_tls(&second_update, &mut server).unwrap();
    assert!(
        !server.wants_write(),
        "write-closed peer queued a second KeyUpdate response"
    );

    client
        .writer()
        .write_all(b"second read epoch")
        .unwrap();
    client_to_server(&mut client, &mut server);
    let mut received = [0u8; 17];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"second read epoch");

    client
        .writer()
        .write_all(b"corrupt me")
        .unwrap();
    let mut malformed = take_client_tls(&mut client);
    *malformed.last_mut().unwrap() ^= 1;
    assert!(feed_server_tls(&malformed, &mut server).is_err());
    assert!(!server.wants_write());
    assert_eq!(
        server
            .writer()
            .write(b"closed")
            .unwrap(),
        0
    );
}

fn assert_no_plaintext(client: &mut ClientConnection) {
    let mut byte = [0u8; 1];
    let error = client
        .reader()
        .read(&mut byte)
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
}

fn take_one_server_write(server: &mut ServerConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    assert_ne!(server.write_tls(&mut wire).unwrap(), 0);
    wire
}

fn take_server_tls(server: &mut ServerConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    while server.wants_write() {
        assert_ne!(server.write_tls(&mut wire).unwrap(), 0);
    }
    wire
}

fn feed_client_tls(wire: &[u8], client: &mut ClientConnection) -> Result<(), rustls::Error> {
    let mut cursor = Cursor::new(wire);
    while (cursor.position() as usize) < cursor.get_ref().len() {
        assert_ne!(client.read_tls(&mut cursor).unwrap(), 0);
        client.process_new_packets()?;
    }
    Ok(())
}

fn tls_record_count(wire: &[u8]) -> usize {
    let mut count = 0;
    let mut offset = 0usize;
    while offset < wire.len() {
        assert!(wire.len() - offset >= 5, "truncated TLS record header");
        let payload_len = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        offset = offset
            .checked_add(5 + payload_len)
            .expect("TLS record length overflow");
        assert!(offset <= wire.len(), "truncated TLS record payload");
        count += 1;
    }
    count
}

fn protected_record_payload_lengths(wire: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut offset = 0usize;
    while offset < wire.len() {
        assert!(wire.len() - offset >= 5, "truncated TLS record header");
        let payload_len = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        let end = offset
            .checked_add(5 + payload_len)
            .expect("TLS record length overflow");
        assert!(end <= wire.len(), "truncated TLS record payload");
        if wire[offset] == 23 {
            lengths.push(payload_len);
        }
        offset = end;
    }
    lengths
}

fn assert_single_protected_record(wire: &[u8], label: &str) {
    assert_eq!(tls_record_count(wire), 1, "{label} was not one TLS record");
    assert_eq!(wire[0], 23, "{label} was not protected application_data");
}

struct PrefixWriter {
    remaining: usize,
    bytes: Vec<u8>,
}

impl PrefixWriter {
    fn new(remaining: usize) -> Self {
        Self {
            remaining,
            bytes: Vec::new(),
        }
    }
}

impl Write for PrefixWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let used = self.remaining.min(buf.len());
        self.bytes
            .extend_from_slice(&buf[..used]);
        self.remaining -= used;
        Ok(used)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn reject_old_epoch_replay(suite: SupportedCipherSuite) {
    let mut client = ClientConnection::new(
        client_config_for_suite(suite),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config_for_suite(suite)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        client_to_server(&mut client, &mut server);
        server_to_client(&mut server, &mut client);
    }

    client
        .writer()
        .write_all(b"captured old epoch")
        .unwrap();
    let old_record = take_client_tls(&mut client);
    feed_server_tls(&old_record, &mut server).unwrap();
    let mut received = [0u8; 18];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"captured old epoch");

    client.refresh_traffic_keys().unwrap();
    client_to_server(&mut client, &mut server);
    server_to_client(&mut server, &mut client);
    let replay = feed_server_tls(&old_record, &mut server);
    assert!(
        replay.is_err(),
        "an old-epoch record was accepted after KeyUpdate"
    );
}

fn accept_unnegotiated_record_size_limit(suite: SupportedCipherSuite) {
    let mut client = ClientConnection::new(
        client_config_for_suite(suite),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config_with_limit(suite, None)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        client_to_server(&mut client, &mut server);
        server_to_client_without_limit_assertion(&mut server, &mut client);
    }
    let payload = vec![0x3c; 2 * CLIENT_RECEIVE_LIMIT];
    server
        .writer()
        .write_all(&payload)
        .unwrap();
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    assert!(
        has_record_larger_than(&wire, CLIENT_RECEIVE_LIMIT),
        "fixture did not contain a record larger than the unnegotiated offer"
    );
    let mut cursor = Cursor::new(wire);
    while (cursor.position() as usize) < cursor.get_ref().len() {
        assert_ne!(client.read_tls(&mut cursor).unwrap(), 0);
        client.process_new_packets().unwrap();
    }
    let mut received = vec![0; payload.len()];
    client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(received, payload);
}

fn fragmented_encrypted_extensions_at_minimum_limit(suite: SupportedCipherSuite) {
    const MINIMUM_RECORD_SIZE_LIMIT: usize = 64;
    const SERVER_MAX_FRAGMENT_SIZE: usize = 32;
    const MAX_FRAGMENT_PLAINTEXT: usize = SERVER_MAX_FRAGMENT_SIZE - 5;
    const MAX_FRAGMENT_CIPHERTEXT: usize = MAX_FRAGMENT_PLAINTEXT + 1 + 16;
    const SHARED_ALPN_LEN: usize = 80;

    let shared_alpn = vec![b'a'; SHARED_ALPN_LEN];
    let mut client_config = client_config_for_suite(suite);
    {
        let config = Arc::get_mut(&mut client_config).unwrap();
        config.record_size_limit =
            Some(rustls::RecordSizeLimit::new(MINIMUM_RECORD_SIZE_LIMIT).unwrap());
        config.alpn_protocols = vec![shared_alpn.clone()];
    }
    let mut server_config = server_config_with_limit(suite, Some(MINIMUM_RECORD_SIZE_LIMIT));
    {
        let config = Arc::get_mut(&mut server_config).unwrap();
        config.max_fragment_size = Some(SERVER_MAX_FRAGMENT_SIZE);
        config.alpn_protocols = vec![shared_alpn.clone()];
    }

    let mut client =
        ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    let client_hello = take_client_tls(&mut client);
    assert!(!client_hello.is_empty());
    feed_server_tls(&client_hello, &mut server).unwrap();

    let server_first_flight = take_server_tls(&mut server);
    let protected_lengths = protected_record_payload_lengths(&server_first_flight);
    // The configured ALPN alone makes EncryptedExtensions larger than three
    // 27-byte fragments, before accounting for the handshake and extension framing.
    assert!(
        protected_lengths.len() >= 4,
        "server flight did not fragment the enlarged EncryptedExtensions"
    );
    assert!(
        protected_lengths[..4]
            .iter()
            .all(|length| *length == MAX_FRAGMENT_CIPHERTEXT),
        "the first four EncryptedExtensions fragments were not full-sized: {protected_lengths:?}"
    );
    assert!(
        protected_lengths
            .iter()
            .all(|length| *length <= MAX_FRAGMENT_CIPHERTEXT),
        "server flight exceeded max_fragment_size on the wire: {protected_lengths:?}"
    );
    assert_protected_record_limit(&server_first_flight, MINIMUM_RECORD_SIZE_LIMIT);
    feed_client_tls(&server_first_flight, &mut client).unwrap();

    for _ in 0..32 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }

        let client_wire = take_client_tls(&mut client);
        if !client_wire.is_empty() {
            assert_protected_record_limit(&client_wire, MINIMUM_RECORD_SIZE_LIMIT);
            feed_server_tls(&client_wire, &mut server).unwrap();
        }

        let server_wire = take_server_tls(&mut server);
        if !server_wire.is_empty() {
            assert_protected_record_limit(&server_wire, MINIMUM_RECORD_SIZE_LIMIT);
            feed_client_tls(&server_wire, &mut client).unwrap();
        }
    }
    assert!(!client.is_handshaking(), "client handshake did not finish");
    assert!(!server.is_handshaking(), "server handshake did not finish");
    assert_eq!(client.alpn_protocol(), Some(shared_alpn.as_slice()));
    assert_eq!(server.alpn_protocol(), Some(shared_alpn.as_slice()));
    assert_eq!(client.negotiated_cipher_suite(), Some(suite));
    assert_eq!(server.negotiated_cipher_suite(), Some(suite));

    let server_payload = vec![0x5c; 4 * MINIMUM_RECORD_SIZE_LIMIT];
    server
        .writer()
        .write_all(&server_payload)
        .unwrap();
    let server_wire = take_server_tls(&mut server);
    let protected_lengths = protected_record_payload_lengths(&server_wire);
    assert!(protected_lengths.len() > 1);
    assert!(
        protected_lengths
            .iter()
            .all(|length| *length <= MAX_FRAGMENT_CIPHERTEXT)
    );
    feed_client_tls(&server_wire, &mut client).unwrap();
    let mut received = vec![0; server_payload.len()];
    client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(received, server_payload);

    let client_payload = vec![0xa3; 4 * MINIMUM_RECORD_SIZE_LIMIT];
    client
        .writer()
        .write_all(&client_payload)
        .unwrap();
    let client_wire = take_client_tls(&mut client);
    let protected_lengths = protected_record_payload_lengths(&client_wire);
    assert!(protected_lengths.len() > 1);
    assert_protected_record_limit(&client_wire, MINIMUM_RECORD_SIZE_LIMIT);
    feed_server_tls(&client_wire, &mut server).unwrap();
    let mut received = vec![0; client_payload.len()];
    server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(received, client_payload);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnbufferedHandshakeState {
    Encoded,
    Transmitted,
    Blocked,
    Writable,
}

fn run_unbuffered_suite(suite: SupportedCipherSuite) {
    let mut client = UnbufferedClientConnection::new(
        client_config_for_suite(suite),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = UnbufferedServerConnection::new(server_config_for_suite(suite)).unwrap();

    complete_unbuffered_handshake(&mut client, &mut server);
    assert_eq!(client.negotiated_cipher_suite(), Some(suite));
    assert_eq!(server.negotiated_cipher_suite(), Some(suite));

    let mut client_wire = encrypt_unbuffered(
        client.process_tls_records(&mut []),
        b"unbuffered client application",
    );
    assert_protected_record_limit(&client_wire, SERVER_RECEIVE_LIMIT);
    let client_wire_len = client_wire.len();
    let received = read_unbuffered(
        server.process_tls_records(client_wire.as_mut_slice()),
        client_wire_len,
    );
    assert_eq!(received, b"unbuffered client application");

    let mut server_wire = encrypt_unbuffered(
        server.process_tls_records(&mut []),
        b"unbuffered server application",
    );
    assert_protected_record_limit(&server_wire, CLIENT_RECEIVE_LIMIT);
    let server_wire_len = server_wire.len();
    let received = read_unbuffered(
        client.process_tls_records(server_wire.as_mut_slice()),
        server_wire_len,
    );
    assert_eq!(received, b"unbuffered server application");

    let mut client_close = queue_unbuffered_close(client.process_tls_records(&mut []));
    assert_single_protected_record(&client_close, "unbuffered client close_notify");
    let client_close_len = client_close.len();
    expect_unbuffered_peer_closed(
        server.process_tls_records(client_close.as_mut_slice()),
        client_close_len,
    );

    let mut server_close = queue_unbuffered_close(server.process_tls_records(&mut []));
    assert_single_protected_record(&server_close, "unbuffered server close_notify");
    let server_close_len = server_close.len();
    expect_unbuffered_peer_closed(
        client.process_tls_records(server_close.as_mut_slice()),
        server_close_len,
    );
    expect_unbuffered_closed(client.process_tls_records(&mut []));
    expect_unbuffered_closed(server.process_tls_records(&mut []));
}

fn complete_unbuffered_handshake(
    client: &mut UnbufferedClientConnection,
    server: &mut UnbufferedServerConnection,
) {
    let mut client_incoming = Vec::new();
    let mut server_incoming = Vec::new();
    let mut client_pending = Vec::new();
    let mut server_pending = Vec::new();

    for _ in 0..256 {
        let (client_discard, client_state) = drive_unbuffered_handshake_status(
            client.process_tls_records(client_incoming.as_mut_slice()),
            &mut client_pending,
            &mut server_incoming,
        );
        assert!(client_discard <= client_incoming.len());
        client_incoming.drain(..client_discard);

        let (server_discard, server_state) = drive_unbuffered_handshake_status(
            server.process_tls_records(server_incoming.as_mut_slice()),
            &mut server_pending,
            &mut client_incoming,
        );
        assert!(server_discard <= server_incoming.len());
        server_incoming.drain(..server_discard);

        if client_state == UnbufferedHandshakeState::Writable
            && server_state == UnbufferedHandshakeState::Writable
        {
            assert!(client_incoming.is_empty());
            assert!(server_incoming.is_empty());
            assert!(client_pending.is_empty());
            assert!(server_pending.is_empty());
            return;
        }

        let progressed = client_discard != 0
            || server_discard != 0
            || matches!(
                client_state,
                UnbufferedHandshakeState::Encoded | UnbufferedHandshakeState::Transmitted
            )
            || matches!(
                server_state,
                UnbufferedHandshakeState::Encoded | UnbufferedHandshakeState::Transmitted
            );
        assert!(progressed, "unbuffered handshake made no progress");
    }

    panic!("unbuffered handshake did not finish");
}

fn drive_unbuffered_handshake_status<Data>(
    status: UnbufferedStatus<'_, '_, Data>,
    pending: &mut Vec<u8>,
    peer_incoming: &mut Vec<u8>,
) -> (usize, UnbufferedHandshakeState) {
    let UnbufferedStatus { discard, state } = status;
    let state = match state.unwrap() {
        ConnectionState::EncodeTlsData(mut state) => {
            let mut encoded = vec![0; 64 * 1024];
            let written = state.encode(&mut encoded).unwrap();
            assert_ne!(written, 0);
            pending.extend_from_slice(&encoded[..written]);
            UnbufferedHandshakeState::Encoded
        }
        ConnectionState::TransmitTlsData(state) => {
            assert!(!pending.is_empty());
            peer_incoming.extend_from_slice(pending);
            pending.clear();
            state.done();
            UnbufferedHandshakeState::Transmitted
        }
        ConnectionState::BlockedHandshake => UnbufferedHandshakeState::Blocked,
        ConnectionState::WriteTraffic(_) => UnbufferedHandshakeState::Writable,
        other => panic!("unexpected unbuffered handshake state: {other:?}"),
    };
    (discard, state)
}

fn encrypt_unbuffered<Data>(status: UnbufferedStatus<'_, '_, Data>, plaintext: &[u8]) -> Vec<u8> {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, 0);
    let mut wire = vec![0; plaintext.len() + 64];
    let written = match state.unwrap() {
        ConnectionState::WriteTraffic(mut state) => state
            .encrypt(plaintext, &mut wire)
            .unwrap(),
        other => panic!("unexpected unbuffered state: {other:?}; wanted WriteTraffic"),
    };
    wire.truncate(written);
    wire
}

fn read_unbuffered<Data>(
    status: UnbufferedStatus<'_, '_, Data>,
    expected_discard: usize,
) -> Vec<u8> {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, expected_discard);
    let mut plaintext = Vec::new();
    match state.unwrap() {
        ConnectionState::ReadTraffic(mut state) => {
            while let Some(record) = state.next_record() {
                let record = record.unwrap();
                assert_eq!(record.discard, 0);
                plaintext.extend_from_slice(record.payload);
            }
        }
        other => panic!("unexpected unbuffered state: {other:?}; wanted ReadTraffic"),
    }
    plaintext
}

fn queue_unbuffered_close<Data>(status: UnbufferedStatus<'_, '_, Data>) -> Vec<u8> {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, 0);
    let mut wire = vec![0; 64];
    let written = match state.unwrap() {
        ConnectionState::WriteTraffic(mut state) => state
            .queue_close_notify(&mut wire)
            .unwrap(),
        other => panic!("unexpected unbuffered state: {other:?}; wanted WriteTraffic"),
    };
    wire.truncate(written);
    wire
}

fn expect_unbuffered_peer_closed<Data>(
    status: UnbufferedStatus<'_, '_, Data>,
    expected_discard: usize,
) {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, expected_discard);
    assert!(matches!(state.unwrap(), ConnectionState::PeerClosed));
}

fn expect_unbuffered_closed<Data>(status: UnbufferedStatus<'_, '_, Data>) {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, 0);
    assert!(matches!(state.unwrap(), ConnectionState::Closed));
}

fn run_openssl_matrix(openssl: &Path) {
    let version = Command::new(openssl)
        .args(["version", "-v"])
        .output()
        .expect("failed to execute supplied OpenSSL binary");
    assert!(version.status.success(), "OpenSSL version command failed");
    let version = String::from_utf8(version.stdout).unwrap();
    assert!(
        version.starts_with("OpenSSL 3.5.7 "),
        "required OpenSSL 3.5.7, got {version:?}"
    );

    for case in suite_cases() {
        rustls_client_with_s_server(openssl, case);
        println!("rustls client/OpenSSL server passed: {}", case.openssl);
        rustls_server_with_s_client(openssl, case);
        println!("rustls server/OpenSSL client passed: {}", case.openssl);
    }
}

fn rustls_client_with_s_server(openssl: &Path, case: SuiteCase) {
    let port = reserve_port();
    let repo = repository_root();
    let cert = repo.join("test-ca/rsa-2048/end.cert");
    let chain = repo.join("test-ca/rsa-2048/inter.cert");
    let key = repo.join("test-ca/rsa-2048/end.key");
    let mut child = ChildGuard::spawn(
        Command::new(openssl)
            .arg("s_server")
            .arg("-accept")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-cert")
            .arg(cert)
            .arg("-cert_chain")
            .arg(chain)
            .arg("-key")
            .arg(key)
            .args(["-tls1_3", "-ciphersuites", case.openssl])
            .args(["-provider", "default", "-naccept", "1", "-rev", "-quiet"]),
    );

    let socket = connect_when_ready(port, &mut child);
    configure_socket(&socket);
    let connection = ClientConnection::new(
        client_config_for_suite(case.rustls),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = StreamOwned::new(connection, socket);

    tls.write_all(b"first epoch\n").unwrap();
    tls.flush().unwrap();
    assert_eq!(read_line(&mut tls), b"hcope tsrif\n");

    tls.conn.refresh_traffic_keys().unwrap();
    tls.write_all(b"next epoch\n").unwrap();
    tls.flush().unwrap();
    assert_eq!(read_line(&mut tls), b"hcope txen\n");
    assert_eq!(tls.conn.negotiated_cipher_suite(), Some(case.rustls));

    tls.conn.send_close_notify();
    tls.flush().unwrap();
    let mut trailing = Vec::new();
    tls.read_to_end(&mut trailing).unwrap();
    assert!(trailing.is_empty());
    let output = child.wait_output(Duration::from_secs(10));
    assert_child_success("OpenSSL s_server", &output);
}

fn rustls_server_with_s_client(openssl: &Path, case: SuiteCase) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let repo = repository_root();
    let ca = repo.join("test-ca/rsa-2048/ca.cert");
    let mut child = ChildGuard::spawn(
        Command::new(openssl)
            .arg("s_client")
            .arg("-connect")
            .arg(format!("127.0.0.1:{port}"))
            .args(["-servername", "localhost", "-verify_hostname", "localhost"])
            .arg("-verify_return_error")
            .arg("-CAfile")
            .arg(ca)
            .args(["-tls1_3", "-ciphersuites", case.openssl])
            .args(["-provider", "default", "-quiet", "-no_ign_eof"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    child
        .stdin()
        .write_all(b"first epoch\nnext epoch\n")
        .unwrap();

    let (socket, _) = listener.accept().unwrap();
    configure_socket(&socket);
    let connection = ServerConnection::new(server_config_for_suite(case.rustls)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);

    assert_eq!(read_line(&mut tls), b"first epoch\n");
    tls.write_all(b"rustls first response\n")
        .unwrap();
    tls.flush().unwrap();
    tls.conn.refresh_traffic_keys().unwrap();
    tls.write_all(b"rustls next response\n")
        .unwrap();
    tls.flush().unwrap();
    assert_eq!(read_line(&mut tls), b"next epoch\n");
    assert_eq!(tls.conn.negotiated_cipher_suite(), Some(case.rustls));

    child.close_stdin();
    let mut trailing = Vec::new();
    tls.read_to_end(&mut trailing).unwrap();
    assert!(trailing.is_empty());
    tls.conn.send_close_notify();
    tls.flush().unwrap();
    tls.sock
        .shutdown(Shutdown::Write)
        .unwrap();

    let output = child.wait_output(Duration::from_secs(10));
    assert_child_success("OpenSSL s_client", &output);
    assert_eq!(
        output.stdout,
        b"rustls first response\nrustls next response\n"
    );
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn connect_when_ready(port: u16, child: &mut ChildGuard) -> TcpStream {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(socket) => return socket,
            Err(error) if Instant::now() < deadline => {
                if let Some(status) = child.try_wait() {
                    panic!("OpenSSL s_server exited before accepting: {status}");
                }
                thread::sleep(Duration::from_millis(20));
                let _ = error;
            }
            Err(error) => panic!("timed out connecting to OpenSSL s_server: {error}"),
        }
    }
}

fn configure_socket(socket: &TcpStream) {
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .unwrap();
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .unwrap();
    socket.set_nodelay(true).unwrap();
}

fn read_line(stream: &mut impl BufRead) -> Vec<u8> {
    let mut line = Vec::new();
    let read = stream
        .read_until(b'\n', &mut line)
        .unwrap();
    assert_ne!(read, 0, "peer closed before sending the expected line");
    line
}

fn assert_child_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(command: &mut Command) -> Self {
        Self {
            child: Some(
                command
                    .spawn()
                    .expect("failed to spawn OpenSSL child"),
            ),
        }
    }

    fn stdin(&mut self) -> &mut impl Write {
        self.child
            .as_mut()
            .unwrap()
            .stdin
            .as_mut()
            .expect("OpenSSL child stdin was not piped")
    }

    fn close_stdin(&mut self) {
        self.child
            .as_mut()
            .unwrap()
            .stdin
            .take();
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
    }

    fn wait_output(&mut self, timeout: Duration) -> Output {
        let deadline = Instant::now() + timeout;
        loop {
            if self.try_wait().is_some() {
                return self
                    .child
                    .take()
                    .unwrap()
                    .wait_with_output()
                    .unwrap();
            }
            assert!(Instant::now() < deadline, "OpenSSL child timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) {
    let wire = take_client_tls(client);
    if wire.is_empty() {
        return;
    }
    assert_protected_record_limit(&wire, SERVER_RECEIVE_LIMIT);
    feed_server_tls(&wire, server).unwrap();
}

fn take_client_tls(client: &mut ClientConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    wire
}

fn feed_server_tls(wire: &[u8], server: &mut ServerConnection) -> Result<(), rustls::Error> {
    let mut cursor = Cursor::new(wire);
    while (cursor.position() as usize) < cursor.get_ref().len() {
        assert_ne!(server.read_tls(&mut cursor).unwrap(), 0);
        server.process_new_packets()?;
    }
    Ok(())
}

fn server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    if wire.is_empty() {
        return;
    }
    assert_protected_record_limit(&wire, CLIENT_RECEIVE_LIMIT);
    let mut cursor = Cursor::new(wire);
    while (cursor.position() as usize) < cursor.get_ref().len() {
        assert_ne!(client.read_tls(&mut cursor).unwrap(), 0);
        client.process_new_packets().unwrap();
    }
}

fn server_to_client_without_limit_assertion(
    server: &mut ServerConnection,
    client: &mut ClientConnection,
) {
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    if wire.is_empty() {
        return;
    }
    let mut cursor = Cursor::new(wire);
    while (cursor.position() as usize) < cursor.get_ref().len() {
        assert_ne!(client.read_tls(&mut cursor).unwrap(), 0);
        client.process_new_packets().unwrap();
    }
}

fn assert_protected_record_limit(wire: &[u8], receive_inner_limit: usize) {
    let mut offset = 0usize;
    while offset < wire.len() {
        assert!(wire.len() - offset >= 5, "truncated TLS record header");
        let payload_len = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        let end = offset + 5 + payload_len;
        assert!(end <= wire.len(), "truncated TLS record payload");
        if wire[offset] == 23 {
            assert!(
                payload_len <= receive_inner_limit + 16,
                "protected record payload {payload_len} exceeded peer limit {receive_inner_limit} plus tag at offset {offset}"
            );
        }
        offset = end;
    }
}

fn has_record_larger_than(wire: &[u8], limit: usize) -> bool {
    let mut offset = 0usize;
    let mut found = false;
    while offset < wire.len() {
        assert!(wire.len() - offset >= 5, "truncated TLS record header");
        let payload_len = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        let end = offset + 5 + payload_len;
        assert!(end <= wire.len(), "truncated TLS record payload");
        found |= payload_len > limit;
        offset = end;
    }
    found
}
