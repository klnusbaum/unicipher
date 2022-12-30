mod cipher;

use anyhow::Result;
use clap::{Args, Parser};
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(value_enum, short, long, default_value_t = CipherType::Simple)]
    cipher: CipherType,
}

#[derive(clap::Subcommand)]
enum Commands {
    Encrypt(CommandArgs),
    Decrypt(CommandArgs),
}

#[derive(Args)]
struct CommandArgs {
    #[arg(short, long)]
    input_file: Option<PathBuf>,

    #[arg(short, long)]
    output_file: Option<PathBuf>,

    content: Option<String>,
}

#[derive(clap::ValueEnum, Clone)]
enum CipherType {
    Simple,
    Hieroglyphs,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Commands::Encrypt(command_args) => encrypt(args.cipher, command_args),
        Commands::Decrypt(command_args) => decrypt(args.cipher, command_args),
    }
    // let encrypted = simple::encrypt_string("adgc")?;
    // println!("Encrytped is: '{}'", encrypted);
    // let decrypted = simple::decrypt_string(&encrypted)?;
    // println!("Decrypted is: '{}'", decrypted);
    // Ok(())
}

fn encrypt(cipher: CipherType, args: CommandArgs) -> Result<()> {
    Ok(())
}

fn decrypt(cipher: CipherType, args: CommandArgs) -> Result<()> {
    Ok(())
}
// Two ciphers.
// One simple.
// The other ensuring the generated unicode lands in the hieroglyphs area
// https://en.wikipedia.org/wiki/Egyptian_Hieroglyphs_(Unicode_block)
