#[macro_use]
extern crate lazy_static;

use std::env;
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::ops::Sub;
use core::str::FromStr;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;
use gethostname::gethostname;
use prometheus::{Encoder, IntGaugeVec, Opts, Registry};
use rustls::pki_types::CertificateDer;
use warp::reject::Rejection;
use warp::reply::Reply;
use warp::Filter;

#[derive(Debug)]
struct CertificateMetric {
    ca: bool,
    subject: String,
    issuer: Option<String>,
    age: i64,
    ttl: i64,
}

#[non_exhaustive]
struct DomainStatus;

impl DomainStatus {
    pub const OK: i64 = 0;
    pub const CERTIFICATE_DECODE_ERROR: i64 = 3;
    pub const CHAIN_EMPTY: i64 = 3;
    pub const HANDSHAKE_FAILED: i64 = 4;
    pub const WRITE_FAILED: i64 = 5;
    pub const CONNECTION_FAILED: i64 = 6;
    pub const CLIENT_CONNECTION_FAILED: i64 = 7;
    pub const INVALID_DOMAIN: i64 = 8;
}

// define prometheus registry and metrics
lazy_static! {

    // Custom registry with prefix and fix label set
    pub static ref REGISTRY: Registry = Registry::new_custom(
        env::var("TLS_CERT_MONITOR_METRIC_PREFIX").ok(),
        Some(
            HashMap::from([
                ("instance".to_string(), env::var("TLS_CERT_MONITOR_INSTANCE").unwrap_or_else(|_| gethostname().to_string_lossy().to_string()))
            ])
            .into_iter()
            .chain(
                match env::var("TLS_CERT_MONITOR_COMMON_LABELS") {
                    Ok(labels) => {
                        labels.split(',')
                        .map(|label| {
                            let parts: Vec<&str> = label.split('=').collect();
                            (parts[0].to_string(), parts[1].to_string())
                        })
                        .collect()
                    },
                    Err(_) => HashMap::new()
                }
            )
            .collect()
        )
    ).expect("Failed to create prometheus registry");

    pub static ref DOMAIN_STATUS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("status", "certificate lifetime in seconds")
            .namespace("domain".to_string()),
        &["domain"]
    )
    .expect("metric can be created");
    pub static ref CERTIFICATE_LIFETIME: IntGaugeVec = IntGaugeVec::new(
        Opts::new("lifetime", "certificate lifetime in seconds")
            .namespace("certificate".to_string()),
        &["domain", "subject", "issuer", "ca"]
    )
    .expect("metric can be created");
    pub static ref CERTIFICATE_AGE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("age", "certificate age in seconds")
            .namespace("certificate".to_string()),
        &["domain", "subject", "issuer", "ca"]
    )
    .expect("metric can be created");
}

fn register_metrics() {
    REGISTRY
        .register(Box::new(DOMAIN_STATUS.clone()))
        .expect("collector can be registered");
    REGISTRY
        .register(Box::new(CERTIFICATE_LIFETIME.clone()))
        .expect("collector can be registered");
    REGISTRY
        .register(Box::new(CERTIFICATE_AGE.clone()))
        .expect("collector can be registered");
}

fn decode_der(certificate: &CertificateDer) -> Option<CertificateMetric> {
    match X509Certificate::from_der(certificate.as_ref()) {
        Ok((_rem, cert)) => {
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

            Some(CertificateMetric {
                ca: cert.is_ca(),
                subject: cert.subject().to_string(),
                issuer: Some(cert.issuer().to_string()),
                age: age.whole_seconds(),
                ttl: ttl.whole_seconds(),
            })
        }
        _ => None,
    }
}

fn check_domain_certificate(domain: String) {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = match domain.clone().try_into() {
        Ok(server_name) => server_name,
        Err(_) => {
            DOMAIN_STATUS
                .with_label_values(&[&domain])
                .set(DomainStatus::INVALID_DOMAIN);
            return;
        }
    };

    let mut conn = match rustls::ClientConnection::new(Arc::new(config.clone()), server_name) {
        Ok(conn) => conn,
        Err(_) => {
            DOMAIN_STATUS
                .with_label_values(&[&domain])
                .set(DomainStatus::CLIENT_CONNECTION_FAILED);
            return;
        }
    };

    let mut sock = match TcpStream::connect(format!("{domain}:443")) {
        Ok(sock) => sock,
        Err(_) => {
            DOMAIN_STATUS
                .with_label_values(&[&domain])
                .set(DomainStatus::CONNECTION_FAILED);
            return;
        }
    };

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let res = tls.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
        )
        .as_bytes(),
    );

    if res.is_err() {
        DOMAIN_STATUS
            .with_label_values(&[&domain])
            .set(DomainStatus::WRITE_FAILED);
        return;
    }

    let certificates = match tls.conn.peer_certificates() {
        Some(certificates) => certificates,
        None => {
            DOMAIN_STATUS
                .with_label_values(&[&domain])
                .set(DomainStatus::HANDSHAKE_FAILED);
            return;
        }
    };

    if certificates.is_empty() {
        DOMAIN_STATUS
            .with_label_values(&[&domain])
            .set(DomainStatus::CHAIN_EMPTY);
        return;
    }

    for certificate in certificates {
        match decode_der(certificate) {
            Some(certificate) => {
                let issuer = certificate.issuer.unwrap_or_else(|| "".to_string());
                let ca = certificate.ca.to_string();
                CERTIFICATE_AGE
                    .with_label_values(&[&domain, &certificate.subject, &issuer, &ca])
                    .set(certificate.age);
                CERTIFICATE_LIFETIME
                    .with_label_values(&[&domain, &certificate.subject, &issuer, &ca])
                    .set(certificate.ttl);
            },
            None => {
                DOMAIN_STATUS
                    .with_label_values(&[&domain])
                    .set(DomainStatus::CERTIFICATE_DECODE_ERROR);
                return;
            }
        };
    }

    DOMAIN_STATUS
        .with_label_values(&[&domain])
        .set(DomainStatus::OK);

    /*
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    println!("{:#?}", ciphersuite);
    */
}

async fn metrics_handler() -> Result<impl Reply, Rejection> {
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    res.push_str(&res_custom);
    Ok(res)
}

async fn data_collector(domains: Vec<String>, interval: u64) {
    let mut collect_interval = tokio::time::interval(Duration::from_secs(interval));
    loop {
        collect_interval.tick().await;
        for domain in &domains {
            check_domain_certificate(domain.to_string());
        }
    }
}

#[tokio::main]
async fn main() {
    // read domains from env var
    let domains =
        env::var("TLS_CERT_MONITOR_DOMAINS").expect("missing env var TLS_CERT_MONITOR_DOMAINS");
    assert!(!domains.is_empty(), "Domain list in env var TLS_CERT_MONITOR_DOMAINS is empty");
    let domains: Vec<String> = domains.split(',').map(|d| d.to_owned()).collect();

    let address = env::var("TLS_CERT_MONITOR_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0".to_string());

    let port = env::var("TLS_CERT_MONITOR_PORT")
        .unwrap_or_default()
        .parse()
        .unwrap_or(8080);

    // read interval from env var
    let interval: u64 = env::var("TLS_CERT_MONITOR_INTERVAL")
        .unwrap_or_default()
        .parse()
        .unwrap_or(30);

    // register static metrics
    register_metrics();

    let metrics_route = warp::path!("metrics").and_then(metrics_handler);

    // start collector task
    tokio::task::spawn(data_collector(domains.clone(), interval));

    // start metrics server
    warp::serve(metrics_route).run(SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(&address).expect("foo")), port)).await;
}
