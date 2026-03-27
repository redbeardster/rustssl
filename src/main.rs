mod cli;
mod verify;
mod certificate;
mod output;
mod completion;
mod chain;
mod ocsp;
mod crl;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use anyhow::Result;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Verify(verify_cmd)) => {
            verify::verify_certificate(verify_cmd)?;
        }
        Some(Commands::Version) => {
            println!("rustssl version {}", env!("CARGO_PKG_VERSION"));
        }
        Some(Commands::Completion { shell }) => {
            completion::generate_completion(shell)?;
        }
        None => {
            println!("{}", Cli::command().render_help());
        }
    }

    Ok(())
}
