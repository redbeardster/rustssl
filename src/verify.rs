use crate::cli::VerifyArgs;
use crate::chain::CertificateChain;
use crate::crl::check_crl;
use crate::ocsp::check_ocsp;
use crate::output::{print_json_output, print_text_output, print_full_output};
use anyhow::{Context, Result};
use native_tls::TlsConnector;
use std::fs;
use std::net::TcpStream;
use std::time::Duration;

pub fn verify_certificate(args: &VerifyArgs) -> Result<()> {
    let addr = format!("{}:{}", args.server, args.port);

    // Разрешаем DNS имя в сокет адрес
    use std::net::ToSocketAddrs;
    let socket_addr = addr.to_socket_addrs()
        .context("Failed to resolve address")?
        .next()
        .context("No addresses found")?;

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

    // Получаем сертификат сервера
    let peer_cert = tls_stream.peer_certificate()
        .context("No certificate received")?
        .context("Server did not provide a certificate")?;

    // Конвертируем в DER формат
    let cert_der = peer_cert.to_der().context("Failed to convert certificate to DER")?;
    let chain_der = vec![cert_der];

    // Создаем структуру цепочки
    let chain = CertificateChain::from_der_chain(&chain_der)?;

    // Сохраняем сертификат в файл если нужно
    if let Some(filename) = &args.save {
        save_certificate_chain(&chain, filename)?;
    }

    // Проверяем OCSP если нужно
    let mut ocsp_status = None;
    if args.check_ocsp {
        let leaf_cert = &chain_der[0];
        let issuer_cert = if chain_der.len() > 1 { Some(&chain_der[1][..]) } else { None };
        ocsp_status = check_ocsp(leaf_cert, issuer_cert)?;
    }

    // Проверяем CRL если нужно
    let mut crl_status = None;
    if args.check_crl {
        let leaf_cert = &chain_der[0];
        crl_status = check_crl(leaf_cert)?;
    }

    // Выводим результат в зависимости от формата
    match args.output.as_str() {
        "json" => print_json_output(&chain, &ocsp_status, &crl_status, args)?,
        "full" => print_full_output(&chain, &ocsp_status, &crl_status, args)?,
        _ => print_text_output(&chain, &ocsp_status, &crl_status, args)?,
    }

    Ok(())
}

fn save_certificate_chain(chain: &CertificateChain, filename: &str) -> Result<()> {
    let mut pem_content = String::new();

    for cert in &chain.certificates {
        let pem = pem::encode_config(
            &pem::Pem::new("CERTIFICATE", cert.der.clone()),
            pem::EncodeConfig::default()
        );
        pem_content.push_str(&pem);
        pem_content.push('\n');
    }

    fs::write(filename, pem_content)
        .context(format!("Failed to save certificate to {}", filename))?;

    println!("💾 Certificate chain saved to: {}", filename);

    Ok(())
}
