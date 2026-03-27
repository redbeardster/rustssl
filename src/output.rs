use crate::cli::VerifyArgs;
use crate::certificate::CertificateInfo;
use anyhow::Result;
use colored::*;
use serde_json;

pub fn print_text_output(cert_info: &CertificateInfo, args: &VerifyArgs) -> Result<()> {
    println!();

    println!("{}: {}", "Server".green().bold(), args.server.cyan());
    println!("{}: {}", "Port".green().bold(), args.port.to_string().cyan());
    println!();

    println!("{}", "Certificate Details:".yellow().bold());
    println!("  {}: {}", "Subject".cyan(), cert_info.subject);
    println!("  {}: {}", "Issuer".cyan(), cert_info.issuer);
    println!("  {}: {}", "Valid From".cyan(), cert_info.not_before);
    println!("  {}: {}", "Valid To".cyan(), cert_info.not_after);

    let expiry_color = if cert_info.days_remaining < 0 {
        "red"
    } else if cert_info.days_remaining < 30 {
        "yellow"
    } else {
        "green"
    };

    let expiry_text = match expiry_color {
        "red" => cert_info.days_remaining.to_string().red(),
        "yellow" => cert_info.days_remaining.to_string().yellow(),
        _ => cert_info.days_remaining.to_string().green(),
    };

    println!("  {}: {} ({} days)",
        "Expires In".cyan(),
        expiry_text,
        cert_info.days_remaining
    );

    println!("  {}: {}", "Serial Number".cyan(), cert_info.serial);
    println!("  {}: {}", "Version".cyan(), cert_info.version);
    println!("  {}: {}", "Signature Algorithm".cyan(), cert_info.signature_algorithm);
    println!("  {}: {}", "Public Key Algorithm".cyan(), cert_info.public_key_algorithm);

    if !cert_info.san_dns.is_empty() {
        println!("  {}:", "Subject Alternative Names".cyan());
        for dns in &cert_info.san_dns {
            println!("    • DNS: {}", dns);
        }
    }

    if !cert_info.san_ips.is_empty() {
        for ip in &cert_info.san_ips {
            println!("    • IP: {}", ip);
        }
    }

    let ca_status = if cert_info.is_ca {
        "Yes".green()
    } else {
        "No".red()
    };
    println!("  {}: {}", "CA Certificate".cyan(), ca_status);

    println!();
    Ok(())
}

pub fn print_json_output(cert_info: &CertificateInfo, args: &VerifyArgs) -> Result<()> {
    let output = serde_json::json!({
        "server": args.server,
        "port": args.port,
        "certificate": cert_info,
        "insecure": args.insecure,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
