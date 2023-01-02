mod cipher;
mod decrypt;
mod encrypt;

use anyhow::Result;
use cipher::{Cipher, Extended, Standard};
use clap::{ArgGroup, Parser};
use decrypt::Decrypter;
use encrypt::Encrypter;
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

    #[arg(value_enum, short, long, default_value_t = CipherType::Standard)]
    cipher: CipherType,

    #[arg(short = 'f', long)]
    input_file: Option<PathBuf>,

    #[arg(short, long)]
    output_file: Option<PathBuf>,

    input: Option<String>,
}

#[derive(clap::ValueEnum, Clone)]
enum CipherType {
    Standard,
    Extended,
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
        match self.cipher {
            CipherType::Standard => self.cipher(reader, &mut writer, Standard {})?,
            CipherType::Extended => self.cipher(reader, &mut writer, Extended {})?,
        }

        writer.flush()?;
        writer.finish()
    }

    fn cipher<R, W, C, const N: usize>(&self, reader: R, writer: W, cipher: C) -> Result<()>
    where
        R: Read,
        W: Write,
        C: Cipher<N>,
    {
        if self.encrypt {
            Encrypter::new(writer, cipher).encrypt(reader)
        } else {
            Decrypter::new(writer, cipher).decrypt(reader)
        }
    }
}

fn from_stdin() -> BufReader<Stdin> {
    BufReader::new(stdin())
}

fn from_file(path: &Path) -> Result<BufReader<File>> {
    Ok(BufReader::new(File::open(path)?))
}

fn from_input(input: &str) -> Cursor<&str> {
    Cursor::new(input)
}

fn to_stdout() -> BufWriter<Stdout> {
    BufWriter::new(stdout())
}

fn to_file(path: &Path) -> Result<BufWriter<File>> {
    let file = OpenOptions::new().write(true).open(path)?;
    Ok(BufWriter::new(file))
}

trait Finish: Sized {
    fn finish(self) -> Result<()> {
        Ok(())
    }
}

impl Finish for BufWriter<File> {}

impl Finish for BufWriter<Stdout> {
    fn finish(mut self) -> Result<()> {
        self.write_all("\n".as_bytes())?;
        Ok(self.flush()?)
    }
}
