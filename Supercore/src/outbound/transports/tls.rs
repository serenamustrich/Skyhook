use std::sync::Arc;

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        Resumption, WebPkiServerVerifier,
    },
    crypto::aws_lc_rs,
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::{config::parse_sha256_certificate_fingerprint, outbound::context::active_dial_context};

#[derive(Debug)]
pub(crate) struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    sha256: [u8; 32],
}

#[derive(Debug)]
struct PinnedCertificateChainVerifier {
    signature_verifier: Arc<dyn ServerCertVerifier>,
    sha256: [u8; 32],
}

impl ServerCertVerifier for PinnedCertificateChainVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if certificate_chain_sha256(end_entity, intermediates) != self.sha256 {
            return Err(rustls::Error::General(
                "server certificate chain SHA-256 pin mismatch".to_string(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

fn certificate_chain_sha256(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> [u8; 32] {
    let mut digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
    for certificate in intermediates {
        let certificate_digest: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        let mut chain = [0u8; 64];
        chain[..32].copy_from_slice(&digest);
        chain[32..].copy_from_slice(&certificate_digest);
        digest = Sha256::digest(chain).into();
    }
    digest
}

pub(crate) fn pinned_certificate_chain_verifier(
    sha256: [u8; 32],
) -> anyhow::Result<Arc<dyn ServerCertVerifier>> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let signature_verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
    Ok(Arc::new(PinnedCertificateChainVerifier {
        signature_verifier,
        sha256,
    }))
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual != self.sha256 {
            return Err(rustls::Error::General(
                "server certificate SHA-256 fingerprint mismatch".to_string(),
            ));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub(crate) fn tls_client_config(skip_cert_verify: bool) -> anyhow::Result<ClientConfig> {
    tls_client_config_with_versions(
        skip_cert_verify,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

pub(crate) fn tls13_client_config(skip_cert_verify: bool) -> anyhow::Result<ClientConfig> {
    tls_client_config_with_versions(skip_cert_verify, &[&rustls::version::TLS13])
}

fn tls_client_config_with_versions(
    skip_cert_verify: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> anyhow::Result<ClientConfig> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verifier: Arc<dyn ServerCertVerifier> = if skip_cert_verify {
        Arc::new(NoCertificateVerification)
    } else {
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?
    };
    let verifier = active_dial_context()
        .and_then(|context| context.certificate_fingerprint)
        .map(|fingerprint| parse_sha256_certificate_fingerprint(&fingerprint))
        .transpose()?
        .map_or(verifier.clone(), |sha256| {
            Arc::new(PinnedCertificateVerifier {
                inner: verifier,
                sha256,
            }) as Arc<dyn ServerCertVerifier>
        });
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::in_memory_sessions(256);
    config.alpn_protocols.clear();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use crate::config::parse_sha256_certificate_fingerprint;

    #[test]
    fn validates_sha256_certificate_fingerprints() {
        let fingerprint = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
        assert_eq!(
            parse_sha256_certificate_fingerprint(fingerprint).unwrap()[0],
            0x00
        );
        assert_eq!(
            parse_sha256_certificate_fingerprint(fingerprint).unwrap()[31],
            0xff
        );
        assert!(parse_sha256_certificate_fingerprint("not-a-fingerprint").is_err());
    }
}
