use crate::cli::VerifyArgs;
use crate::certificate::CertificateInfo;
use crate::output::{print_json_output, print_text_output};
use anyhow::{Context, Result};
use native_tls::TlsConnector;
use std::net::TcpStream;
use std::time::Duration;

pub fn verify_certificate(args: &VerifyArgs) -> Result<()> {
    // Сначала пытаемся распарсить как IP:port
    let socket_addr = match format!("{}:{}", args.server, args.port).parse() {
        Ok(addr) => addr,
        Err(_) => {
            // Если не получилось, то это доменное имя - разрешаем DNS
            use std::net::ToSocketAddrs;
            format!("{}:{}", args.server, args.port)
                .to_socket_addrs()
                .context("Failed to resolve address")?
                .next()
                .context("No addresses found")?
        }
    };

    // Подключаемся по TCP с таймаутом
    let stream = TcpStream::connect_timeout(
        &socket_addr,
        Duration::from_secs(args.timeout),
    ).context("Failed to connect")?;

    // Создаем TLS коннектор
    let connector = if args.insecure {
        TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?
    } else {
        TlsConnector::builder().build()?
    };

    // Устанавливаем TLS соединение
    let tls_stream = connector
        .connect(&args.server, stream)
        .context("TLS handshake failed")?;

    // Получаем сертификат в формате DER (native-tls::Certificate)
    let cert = tls_stream.peer_certificate()
        .context("No certificate received")?
        .context("Certificate chain is empty")?;

    // Конвертируем Certificate в bytes (to_der возвращает Result)
    let cert_der = cert.to_der()
        .context("Failed to convert certificate to DER")?;

    // Парсим DER в X509 сертификат
    let (_, parsed_cert) = x509_parser::parse_x509_certificate(&cert_der)
        .context("Failed to parse certificate")?;

    let cert_info = CertificateInfo::from_x509(&parsed_cert);

    // Выводим результат
    match args.output.as_str() {
        "json" => print_json_output(&cert_info, args)?,
        _ => print_text_output(&cert_info, args)?,
    }

    // Проверяем срок действия
    if cert_info.days_remaining < 0 {
        anyhow::bail!("Certificate has expired");
    } else if cert_info.days_remaining < 30 {
        eprintln!("⚠️  Warning: Certificate expires in {} days", cert_info.days_remaining);
    }

    Ok(())
}
