use anyhow::Result;
use x509_parser::prelude::*;
use reqwest::blocking::Client;
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CrlStatus {
    pub is_revoked: bool,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub revocation_date: Option<DateTime<Utc>>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub this_update: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub next_update: Option<DateTime<Utc>>,
}

pub fn check_crl(cert_der: &[u8]) -> Result<Option<CrlStatus>> {
    let (_, cert) = parse_x509_certificate(cert_der)?;

    // Извлекаем CRL URL
    let crl_url = extract_crl_url(&cert);

    if crl_url.is_none() {
        return Ok(None);
    }

    let crl_url = crl_url.unwrap();
    println!("  🔍 Checking CRL: {}", crl_url);

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match client.get(&crl_url).send() {
        Ok(response) => {
            if response.status().is_success() {
                let crl_data = response.bytes()?;
                let (_, crl) = parse_x509_crl(&crl_data)?;

                // Проверяем, есть ли сертификат в CRL
                let serial = cert.raw_serial();
                let is_revoked = crl.tbs_cert_list.revoked_certificates.iter().any(|revoked| {
                    revoked.user_certificate.to_bytes_be() == serial
                });

                Ok(Some(CrlStatus {
                    is_revoked,
                    revocation_date: None, // Можно извлечь из CRL
                    this_update: Utc::now(),
                    next_update: None,
                }))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            eprintln!("  ⚠️  CRL check failed: {}", e);
            Ok(None)
        }
    }
}

fn extract_crl_url(cert: &X509Certificate) -> Option<String> {
    for ext in cert.extensions() {
        if ext.oid == oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
            if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
                if let Some(point) = points.points.first() {
                    if let Some(name) = &point.distribution_point {
                        if let DistributionPointName::FullName(names) = name {
                            for general_name in names {
                                if let GeneralName::URI(uri) = general_name {
                                    return Some(uri.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn print_crl_status(status: &CrlStatus) {
    if status.is_revoked {
        println!("  {} ❌ Certificate is in CRL", "CRL Status:".red().bold());
        if let Some(date) = status.revocation_date {
            println!("  {} {}", "Revoked at:".red(), date);
        }
    } else {
        println!("  {} ✓ Not in CRL", "CRL Status:".green().bold());
    }
    println!("  {} {}", "This update:".cyan(), status.this_update);
    if let Some(next) = &status.next_update {
        println!("  {} {}", "Next update:".cyan(), next);
    }
}
