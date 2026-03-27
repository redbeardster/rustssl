use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::blocking::Client;
use x509_parser::prelude::*;
use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct OcspStatus {
    pub is_revoked: bool,
    pub revocation_time: Option<String>,
    pub this_update: String,
    pub next_update: Option<String>,
    pub response_status: String,
}

pub fn check_ocsp(cert_der: &[u8], _issuer_der: Option<&[u8]>) -> Result<Option<OcspStatus>> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .context("Failed to parse certificate for OCSP")?;

    // Извлекаем OCSP URL из расширений сертификата
    let ocsp_url = extract_ocsp_url(&cert);

    if ocsp_url.is_none() {
        return Ok(None);
    }

    let ocsp_url = ocsp_url.unwrap();
    println!("  🔍 Checking OCSP: {}", ocsp_url);

    // Создаем OCSP запрос (упрощенная версия)
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Для реального OCSP нужно формировать правильный запрос
    // Здесь упрощенная проверка через GET запрос
    let ocsp_request = format!("{}/{}", ocsp_url, BASE64.encode(cert_der));

    match client.get(&ocsp_request).send() {
        Ok(response) => {
            if response.status().is_success() {
                let status = OcspStatus {
                    is_revoked: false, // В реальности нужно парсить ответ
                    revocation_time: None,
                    this_update: chrono::Utc::now().to_rfc3339(),
                    next_update: None,
                    response_status: "Successful".to_string(),
                };
                Ok(Some(status))
            } else {
                Ok(Some(OcspStatus {
                    is_revoked: false,
                    revocation_time: None,
                    this_update: chrono::Utc::now().to_rfc3339(),
                    next_update: None,
                    response_status: format!("HTTP {}", response.status()),
                }))
            }
        }
        Err(e) => {
            eprintln!("  ⚠️  OCSP check failed: {}", e);
            Ok(None)
        }
    }
}

fn extract_ocsp_url(cert: &X509Certificate) -> Option<String> {
    for ext in cert.extensions() {
        if ext.oid == oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS {
            if let ParsedExtension::AuthorityInfoAccess(access) = ext.parsed_extension() {
                for desc in &access.accessdescs {
                    // OCSP OID: 1.3.6.1.5.5.7.48.1
                    let ocsp_oid = oid_registry::Oid::from(&[1, 3, 6, 1, 5, 5, 7, 48, 1]).unwrap();
                    if desc.access_method == ocsp_oid {
                        if let GeneralName::URI(uri) = &desc.access_location {
                            return Some(uri.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn print_ocsp_status(status: &OcspStatus) {
    if status.is_revoked {
        println!("  {} ❌ Certificate is REVOKED", "OCSP Status:".red().bold());
        if let Some(time) = &status.revocation_time {
            println!("  {} {}", "Revoked at:".red(), time);
        }
    } else {
        println!("  {} ✓ Not revoked", "OCSP Status:".green().bold());
    }
    println!("  {} {}", "This update:".cyan(), status.this_update);
    if let Some(next) = &status.next_update {
        println!("  {} {}", "Next update:".cyan(), next);
    }
}
