use rustls::pki_types::CertificateDer;
use core::ops::Sub;
use std::io::{Write};
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

#[derive(Debug)]
struct CertificateMetric {
    valid: bool,
    ca: bool,
    subject: Option<String>,
    issuer: Option<String>,
    age: Option<u64>,
    ttl: Option<u64>
}

fn decode_der(certificate: &CertificateDer) -> CertificateMetric {
    match X509Certificate::from_der(certificate.as_ref()) {
        Ok((rem, cert)) => {
            // optional check if there is data remaining
            // skipped for now
            // assert!(rem.is_empty());
            let now = ASN1Time::now();

            let age = now
                .sub(cert.validity.not_before)
                .unwrap_or_else(|| cert.validity.not_before.sub(now).unwrap());
            let ttl = now
                .sub(cert.validity.not_after)
                .unwrap_or_else(|| cert.validity.not_after.sub(now).unwrap());

            CertificateMetric {
                valid: cert.validity.is_valid(),
                ca: cert.is_ca(),
                subject: Some(cert.subject().to_string()),
                issuer: Some(cert.issuer().to_string()),
                age: Some(age.whole_seconds() as u64),
                ttl: Some(ttl.whole_seconds() as u64)
            }
        }
        _ => CertificateMetric {
            valid: false,
            ca: false,
            subject: None,
            issuer: None,
            age: None,
            ttl: None
        }
    }
}

fn check_domain_certificate(domain: String) {

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = domain.clone().try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config.clone()), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{domain}:443")).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let certificates = tls.conn.peer_certificates().unwrap();

    let metric = decode_der(certificates.first().unwrap());
    println!("{:#?}", metric);

    for cert in certificates.iter().skip(1) {
        let metric = decode_der(cert);
        println!("{:#?}", metric);
    }

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();

    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();

    /*
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
    */

}

fn main() {

    let domain = "www.sos-kinderdorf.de".to_string();
    check_domain_certificate(domain);
}
