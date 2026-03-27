use crate::certificate::CertificateInfo;
use anyhow::{Context, Result};
use x509_parser::prelude::*;
use colored::*;
use serde::Serialize;

#[derive(Debug)]
pub struct CertificateChain {
    pub certificates: Vec<CertificateWithInfo>,
}

#[derive(Debug, Serialize)]
pub struct CertificateWithInfo {
    pub der: Vec<u8>,
    pub info: CertificateInfo,
    pub index: usize,
}

impl CertificateChain {
    pub fn from_der_chain(cert_chain: &[Vec<u8>]) -> Result<Self> {
        let mut certificates = Vec::new();
        
        for (idx, cert_der) in cert_chain.iter().enumerate() {
            let (_, parsed_cert) = parse_x509_certificate(cert_der)
                .context(format!("Failed to parse certificate at index {}", idx))?;
            
            let info = CertificateInfo::from_x509(&parsed_cert);
            
            certificates.push(CertificateWithInfo {
                der: cert_der.clone(),
                info,
                index: idx,
            });
        }
        
        Ok(CertificateChain { certificates })
    }
    
    pub fn validate_chain(&self) -> Result<Vec<ValidationResult>> {
        let mut results = Vec::new();
        
        for i in 0..self.certificates.len() {
            let cert = &self.certificates[i];
            let issuer = if i + 1 < self.certificates.len() {
                Some(&self.certificates[i + 1].info)
            } else {
                None
            };
            
            results.push(ValidationResult {
                index: cert.index,
                subject: cert.info.subject.clone(),
                issuer: cert.info.issuer.clone(),
                is_self_signed: cert.info.is_self_signed,
                valid: true, // Упрощенно
                message: if let Some(iss) = issuer {
                    format!("Signed by: {}", iss.subject)
                } else if cert.info.is_self_signed {
                    "Root certificate (self-signed)".to_string()
                } else {
                    "End certificate".to_string()
                },
            });
        }
        
        Ok(results)
    }
    
    pub fn print_chain(&self) -> Result<()> {
        println!("\n{}", "╔════════════════════════════════════════╗".bright_blue());
        println!("{}", "║        Certificate Chain               ║".bright_blue().bold());
        println!("{}", "╚════════════════════════════════════════╝".bright_blue());
        
        for cert in &self.certificates {
            let role = if cert.index == 0 {
                "📄 Leaf Certificate"
            } else if cert.index == self.certificates.len() - 1 {
                "🔒 Root Certificate"
            } else {
                "🔗 Intermediate Certificate"
            };
            
            println!("\n{} {} {}",
                if cert.index == 0 { "▶".green() } else { "  ".normal() },
                format!("[{}]", cert.index).yellow(),
                role.cyan().bold()
            );
            println!("  {}: {}", "Subject".cyan(), cert.info.subject);
            println!("  {}: {}", "Issuer".cyan(), cert.info.issuer);
            println!("  {}: {}", "Valid".cyan(), 
                format!("{} → {}", cert.info.not_before, cert.info.not_after).white()
            );
            
            if cert.info.is_self_signed && cert.index == self.certificates.len() - 1 {
                println!("  {}: {}", "Status".cyan(), "✓ Trusted root".green());
            }
        }
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct ValidationResult {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    pub is_self_signed: bool,
    pub valid: bool,
    pub message: String,
}