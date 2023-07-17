use std::sync::Arc;

mod aead;
mod hash;
mod hmac;
mod kx;
mod verify;

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
        },
        hmac_provider: &hmac::Sha256Hmac,
        aead_alg: &aead::Chacha20Poly1305,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
        },
        kx: rustls::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        fixed_iv_len: 12,
        aead_key_len: 32,
        explicit_nonce_len: 0,
        hmac_provider: &hmac::Sha256Hmac,
        aead_alg: &aead::Chacha20Poly1305,
    });

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub struct Provider;

impl Provider {
    pub fn certificate_verifier(
        roots: rustls::RootCertStore,
    ) -> Arc<dyn rustls::client::ServerCertVerifier> {
        Arc::new(rustls::client::WebPkiServerVerifier::new_with_algorithms(
            roots,
            verify::ALGORITHMS,
        ))
    }
}

impl rustls::crypto::CryptoProvider for Provider {
    type KeyExchange = kx::KeyExchange;

    fn fill_random(bytes: &mut [u8]) -> Result<(), rustls::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::GetRandomFailed)
    }

    fn default_cipher_suites() -> &'static [rustls::SupportedCipherSuite] {
        &ALL_CIPHER_SUITES
    }
}
