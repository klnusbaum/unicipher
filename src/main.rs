mod cipher;

use anyhow::Result;
use cipher::{Algorithm, Cipher, Extended, Standard};
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
        {
            let buf_reader = BufReader::new(reader);
            let mut buf_writer = BufWriter::new(&mut writer);
            match self.cipher {
                CipherType::Standard => {
                    self.cipher(buf_reader, &mut buf_writer, Cipher::new(Standard {}))?
                }
                CipherType::Extended => {
                    self.cipher(buf_reader, &mut buf_writer, Cipher::new(Extended {}))?
                }
            }

            buf_writer.flush()?;
        }

        writer.finish()
    }

    fn cipher<R, W, A, const N: usize>(
        &self,
        reader: R,
        mut writer: W,
        cipher: Cipher<A, N>,
    ) -> Result<()>
    where
        R: Read,
        W: Write,
        A: Algorithm<N>,
    {
        if self.encrypt {
            cipher.encrypt(reader, &mut writer)
        } else {
            cipher.decrypt(reader, &mut writer)
        }
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
        self.write_all("\n".as_bytes())?;
        Ok(self.flush()?)
    }
}
