use clap::{Parser, Subcommand, Args};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "rustssl")]
#[command(author, version, about = "Simple CLI app for checking SSL certificates", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Verify SSL certificate
    Verify(VerifyArgs),

    /// Print version information
    Version,

    /// Generate autocompletion script for the specified shell
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// DNS name or IP address to verify
    #[arg(short, long, required = true)]
    pub server: String,

    /// Port number (default: 443)
    #[arg(short, long, default_value = "443")]
    pub port: u16,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Connection timeout in seconds (default: 10)
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Disable certificate verification (insecure)
    #[arg(long)]
    pub insecure: bool,
}
