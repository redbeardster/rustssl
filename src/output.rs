use crate::cli::VerifyArgs;
use crate::chain::CertificateChain;
use crate::crl::CrlStatus;
use crate::ocsp::OcspStatus;
use anyhow::Result;
use colored::*;

pub fn print_text_output(
    chain: &CertificateChain,
    ocsp_status: &Option<OcspStatus>,
    crl_status: &Option<CrlStatus>,
    args: &VerifyArgs,
) -> Result<()> {
    let leaf = &chain.certificates[0].info;

    println!("{}", "╔════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║     SSL Certificate Information       ║".bright_cyan().bold());
    println!("{}", "╚════════════════════════════════════════╝".bright_cyan());
    println!();

    println!("{}: {}", "Server".green().bold(), args.server.cyan());
    println!("{}: {}", "Port".green().bold(), args.port.to_string().cyan());
    println!();

    println!("{}", "Certificate Details:".yellow().bold());
    println!("  {}: {}", "Subject".cyan(), leaf.subject);
    println!("  {}: {}", "Issuer".cyan(), leaf.issuer);
    println!("  {}: {}", "Valid From".cyan(), leaf.not_before);
    println!("  {}: {}", "Valid To".cyan(), leaf.not_after);

    let expiry_color = if leaf.days_remaining < 0 {
        "red"
    } else if leaf.days_remaining < 30 {
        "yellow"
    } else {
        "green"
    };

    let expiry_text = match expiry_color {
        "red" => leaf.days_remaining.to_string().red(),
        "yellow" => leaf.days_remaining.to_string().yellow(),
        _ => leaf.days_remaining.to_string().green(),
    };

    println!("  {}: {} ({} days)",
        "Expires In".cyan(),
        expiry_text,
        leaf.days_remaining
    );

    println!("  {}: {}", "Serial Number".cyan(), leaf.serial);
    println!("  {}: {}", "Version".cyan(), leaf.version);
    println!("  {}: {}", "Self-signed".cyan(),
        if leaf.is_self_signed { "Yes".yellow() } else { "No".green() });

    if !leaf.san_dns.is_empty() {
        println!("  {}:", "Subject Alternative Names".cyan());
        for dns in leaf.san_dns.iter().take(10) {
            println!("    • DNS: {}", dns);
        }
        if leaf.san_dns.len() > 10 {
            println!("    • ... and {} more", leaf.san_dns.len() - 10);
        }
    }

    let ca_status = if leaf.is_ca {
        "Yes".yellow()
    } else {
        "No".green()
    };
    println!("  {}: {}", "CA Certificate".cyan(), ca_status);

    // Показываем OCSP статус
    if let Some(ocsp) = ocsp_status {
        println!();
        println!("{}", "Revocation Status:".yellow().bold());
        print_ocsp_status(ocsp);
    }

    // Показываем CRL статус
    if let Some(crl) = crl_status {
        print_crl_status(crl);
    }

    // Показываем цепочку если нужно
    if args.show_chain {
        chain.print_chain()?;
    }

    println!();
    Ok(())
}

pub fn print_full_output(
    chain: &CertificateChain,
    ocsp_status: &Option<OcspStatus>,
    crl_status: &Option<CrlStatus>,
    args: &VerifyArgs,
) -> Result<()> {
    // Сначала показываем текстовый вывод
    print_text_output(chain, ocsp_status, crl_status, args)?;

    // Затем показываем полную цепочку
    println!("\n{}", "════════════════════════════════════════".bright_black());
    chain.print_chain()?;

    Ok(())
}

pub fn print_json_output(
    chain: &CertificateChain,
    ocsp_status: &Option<OcspStatus>,
    crl_status: &Option<CrlStatus>,
    args: &VerifyArgs,
) -> Result<()> {
    let output = serde_json::json!({
        "server": args.server,
        "port": args.port,
        "certificate_chain": chain.certificates,
        "ocsp": ocsp_status,
        "crl": crl_status,
        "insecure": args.insecure,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

// Импортируем функции из других модулей
use crate::ocsp::print_ocsp_status;
use crate::crl::print_crl_status;
