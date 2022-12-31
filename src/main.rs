mod cipher;

use anyhow::{Error, Result};
use cipher::{simple, Decrypt, Encrypt};
use clap::{ArgGroup, Parser};
use std::fs::{File, OpenOptions};
use std::io::{stdin, stdout, BufReader, BufWriter, Cursor, Read, Write};
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
#[command(group(
        ArgGroup::new("action")
        .multiple(false)
        .required(true)
        .args(["decrypt", "encrypt"]),
        ))]
struct Cli {
    #[arg(short, long)]
    decrypt: bool,

    #[arg(short, long)]
    encrypt: bool,

    #[arg(value_enum, short, long, default_value_t = CipherType::Simple)]
    cipher: CipherType,

    #[arg(short = 'f', long)]
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
    args.run()
}

impl Cli {
    fn run(&self) -> Result<()> {
        match &self.cipher {
            CipherType::Simple => self.with_cipher(simple::Cipher::new()),
            CipherType::Hieroglyphs => Ok(()),
        }
    }

    fn with_cipher<C>(&self, cipher: C) -> Result<()>
    where
        C: Encrypt + Decrypt,
    {
        if let Some(content) = &self.content {
            self.with_reader(cipher, &mut Cursor::new(content))
        } else if let Some(file_name) = &self.input_file {
            self.with_reader(cipher, File::open(file_name)?)
        } else {
            self.with_reader(cipher, stdin())
        }
    }

    fn with_reader<R, C>(&self, cipher: C, reader: R) -> Result<()>
    where
        C: Encrypt + Decrypt,
        R: Read,
    {
        if let Some(file_name) = &self.output_file {
            let mut file = OpenOptions::new().write(true).open(file_name)?;
            self.with_reader_and_writer(cipher, reader, &mut file)
        } else {
            self.with_reader_and_writer(cipher, reader, &mut stdout())?;
            finish_stdout()
        }
    }

    fn with_reader_and_writer<C, R, W>(&self, cipher: C, reader: R, writer: &mut W) -> Result<()>
    where
        C: Encrypt + Decrypt,
        R: Read,
        W: Write,
    {
        let reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);
        if self.encrypt {
            cipher.encrypt(reader, &mut writer)
        } else {
            cipher.decrypt(reader, &mut writer)
        }?;
        Ok(writer.flush()?)
    }
}

fn finish_stdout() -> Result<()> {
    Ok(stdout().write_all("\n".as_bytes())?)
}
