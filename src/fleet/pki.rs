//! Certificate authority, CSR signing and rustls configs.
//!
//! Trust model (similar to kubeadm/k3s):
//!  * `server init` creates a private CA and a server certificate.
//!  * An admin creates a one-time token; the agent enrolls pinning the *server certificate
//!    fingerprint* (printed alongside the token), so a man-in-the-middle cannot capture the token.
//!  * The agent sends a CSR (its private key never leaves the host); the server signs it.
//!  * From then on both sides use mutual TLS verified against the private CA.

use super::util::{current_year, sha256_hex};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::net::IpAddr;
use std::sync::Arc;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

pub struct ServerPki {
    pub ca_pem: String,
    pub ca_key_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Create a fresh CA and a server certificate valid for `names` (DNS names or IPs).
pub fn init_server(names: &[String]) -> Res<ServerPki> {
    let y = current_year();

    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.distinguished_name.push(DnType::CommonName, "netwatch CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = date_time_ymd(y - 1, 1, 1);
    ca_params.not_after = date_time_ymd(y + 30, 1, 1);
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, &ca_key);

    let mut sp = CertificateParams::new(Vec::<String>::new())?;
    sp.subject_alt_names = names
        .iter()
        .map(|n| match n.parse::<IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => Ok(SanType::DnsName(n.clone().try_into()?)),
        })
        .collect::<Result<_, rcgen::Error>>()?;
    sp.distinguished_name.push(DnType::CommonName, "netwatch-server");
    sp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    sp.not_before = date_time_ymd(y - 1, 1, 1);
    sp.not_after = date_time_ymd(y + 10, 1, 1);
    let skey = KeyPair::generate()?;
    let scert = sp.signed_by(&skey, &issuer)?;

    Ok(ServerPki {
        ca_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        cert_pem: scert.pem(),
        key_pem: skey.serialize_pem(),
    })
}

pub fn der_from_pem(pem: &str) -> Res<CertificateDer<'static>> {
    Ok(CertificateDer::from_pem_slice(pem.as_bytes())?)
}

pub fn fingerprint(cert_pem: &str) -> Res<String> {
    Ok(sha256_hex(der_from_pem(cert_pem)?.as_ref()))
}

/// Sign an agent CSR with the CA. Returns the client certificate PEM.
pub fn sign_csr(csr_pem: &str, ca_pem: &str, ca_key_pem: &str, cn: &str) -> Res<String> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(ca_pem, ca_key)?;
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let y = current_year();
    // Never trust what the CSR asks for beyond the key: force identity, usage and validity.
    csr.params.subject_alt_names.clear();
    csr.params.distinguished_name = rcgen::DistinguishedName::new();
    csr.params.distinguished_name.push(DnType::CommonName, cn);
    csr.params.is_ca = IsCa::ExplicitNoCa;
    csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    csr.params.not_before = date_time_ymd(y - 1, 1, 1);
    csr.params.not_after = date_time_ymd(y + 5, 1, 1);
    Ok(csr.signed_by(&issuer)?.pem())
}

/// Generate an agent keypair and a CSR. Returns (private key PEM, CSR PEM).
pub fn agent_csr(hostname: &str) -> Res<(String, String)> {
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::CommonName, hostname);
    let csr = p.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

pub fn server_config(ca_pem: &str, cert_pem: &str, key_pem: &str) -> Res<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(der_from_pem(ca_pem)?)?;
    // Unauthenticated clients are allowed at the TLS layer only so they can enroll; the
    // application layer rejects everything except Enroll for them.
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .allow_unauthenticated()
        .build()?;
    let chain = vec![der_from_pem(cert_pem)?];
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Arc::new(cfg))
}

/// Config for an enrolled agent: verifies the server against our CA and presents a client cert.
pub fn agent_config(ca_pem: &str, cert_pem: &str, key_pem: &str) -> Res<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(der_from_pem(ca_pem)?)?;
    let chain = vec![der_from_pem(cert_pem)?];
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    Ok(Arc::new(cfg))
}

/// Config for the enrollment handshake: no client cert, server trusted only if its certificate
/// matches the pinned SHA-256 fingerprint.
pub fn enroll_config(pin: &str) -> Res<Arc<ClientConfig>> {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            pin: pin.trim().to_lowercase().replace(':', ""),
            provider: provider(),
        }))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha256_hex(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned fingerprint".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
