use crate::cli::Cli;
use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

pub fn generate_completion(shell: &Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let bin_name = "rustssl".to_string();

    generate(*shell, &mut cmd, bin_name, &mut io::stdout());

    Ok(())
}
