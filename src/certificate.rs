use serde::Serialize;
use chrono::{Utc, TimeZone};
use x509_parser::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub version: u32,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub san_dns: Vec<String>,
    pub san_ips: Vec<String>,
    pub is_ca: bool,
    pub days_remaining: i64,
}

impl CertificateInfo {
    pub fn from_x509(cert: &X509Certificate) -> Self {
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        // Конвертируем ASN1Time в читаемый формат
        let not_before = format_asn1_time(cert.validity().not_before);
        let not_after = format_asn1_time(cert.validity().not_after);

        let serial = cert
            .raw_serial()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // Конвертируем X509Version в u32 (обрабатываем все возможные значения)
        let version = match cert.version() {
            X509Version::V1 => 1,
            X509Version::V2 => 2,
            X509Version::V3 => 3,
            X509Version(other) => other, // Для других значений используем число
        };

        let signature_algorithm = format!("{:?}", cert.signature_algorithm);
        let public_key_algorithm = format!("{:?}", cert.public_key().algorithm);

        // Извлекаем SAN
        let mut san_dns = Vec::new();
        let mut san_ips = Vec::new();

        for ext in cert.extensions() {
            if ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
                // parsed_extension() возвращает &ParsedExtension
                match ext.parsed_extension() {
                    ParsedExtension::SubjectAlternativeName(san) => {
                        for name in san.general_names.iter() {
                            match name {
                                GeneralName::DNSName(dns) => {
                                    san_dns.push(dns.to_string());
                                }
                                GeneralName::IPAddress(ip) => {
                                    if let Ok(ip_str) = std::str::from_utf8(ip) {
                                        san_ips.push(ip_str.to_string());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Проверяем, является ли сертификат CA
        let mut is_ca = false;
        for ext in cert.extensions() {
            if ext.oid == oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS {
                match ext.parsed_extension() {
                    ParsedExtension::BasicConstraints(bc) => {
                        is_ca = bc.ca;
                        break;
                    }
                    _ => {}
                }
            }
        }

        // Рассчитываем оставшиеся дни
        let days_remaining = calculate_days_remaining(cert.validity().not_after);

        CertificateInfo {
            subject,
            issuer,
            not_before,
            not_after,
            serial,
            version,
            signature_algorithm,
            public_key_algorithm,
            san_dns,
            san_ips,
            is_ca,
            days_remaining,
        }
    }
}

fn format_asn1_time(time: x509_parser::time::ASN1Time) -> String {
    // to_datetime() возвращает OffsetDateTime (из крейта time)
    let dt = time.to_datetime();
    format!("{}", dt)
}

fn calculate_days_remaining(not_after: x509_parser::time::ASN1Time) -> i64 {
    let now = Utc::now();
    let expiry_dt = not_after.to_datetime();

    // Конвертируем time::OffsetDateTime в chrono::DateTime<Utc>
    let expiry = Utc.timestamp_opt(expiry_dt.unix_timestamp(), 0).unwrap();

    (expiry - now).num_days()
}
