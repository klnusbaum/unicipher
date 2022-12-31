mod cipher;

use anyhow::Result;
use cipher::{simple, Decrypt, Encrypt};
use clap::{ArgGroup, Parser};
use std::fs::{File, OpenOptions};
use std::io::{stdin, stdout, BufReader, BufWriter, Cursor, Read, Stdin, Stdout, Write};
use std::path::{Path, PathBuf};

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

    input: Option<String>,
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
        if let (Some(input_file), Some(output_file)) = (&self.input_file, &self.output_file) {
            self.write(from_file(input_file)?, to_file(output_file)?)
        } else if let (Some(input), Some(output_file)) = (&self.input, &self.output_file) {
            self.write(from_input(input), to_file(output_file)?)
        } else if let Some(output_file) = &self.output_file {
            self.write(from_stdin(), to_file(output_file)?)
        } else if let Some(input_file) = &self.input_file {
            self.write(from_file(input_file)?, to_stdout())
        } else if let Some(input) = &self.input {
            self.write(from_input(input), to_stdout())
        } else {
            self.write(from_stdin(), to_stdout())
        }
    }

    fn write<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: Read,
        W: Write + Finish,
    {
        {
            let buf_reader = BufReader::new(reader);
            let mut buf_writer = BufWriter::new(&mut writer);
            if self.encrypt {
                self.cipher.encrypt(buf_reader, &mut buf_writer)
            } else {
                self.cipher.decrypt(buf_reader, &mut buf_writer)
            }?;
            buf_writer.flush()?;
        }

        writer.finish()
    }
}

fn from_stdin() -> Stdin {
    stdin()
}

fn from_file(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
}

fn from_input(input: &str) -> Cursor<&str> {
    Cursor::new(input)
}

fn to_stdout() -> Stdout {
    stdout()
}

fn to_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).open(path)?)
}

trait Finish: Sized {
    fn finish(self) -> Result<()> {
        Ok(())
    }
}

impl Finish for File {}

impl Finish for Stdout {
    fn finish(mut self) -> Result<()> {
        self.write("\n".as_bytes())?;
        Ok(self.flush()?)
    }
}

impl CipherType {
    fn encrypt<R: Read, W: Write>(&self, reader: R, writer: &mut W) -> Result<()> {
        match self {
            CipherType::Simple => simple::Cipher::new().encrypt(reader, writer),
            CipherType::Hieroglyphs => Ok(()),
        }
    }

    fn decrypt<R: Read, W: Write>(&self, reader: R, writer: &mut W) -> Result<()> {
        match self {
            CipherType::Simple => simple::Cipher::new().decrypt(reader, writer),
            CipherType::Hieroglyphs => Ok(()),
        }
    }
}
