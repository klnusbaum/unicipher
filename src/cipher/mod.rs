mod bytepairs;
mod chars;
mod extended;
mod nbytes;
mod standard;
#[cfg(test)]
mod tests;

pub use extended::Extended;
pub use standard::Standard;

use anyhow::Result;
use bytepairs::BytePairs;
use nbytes::NBytes;
use std::io::{Read, Write};

pub trait Cipher<const N: usize> {
    fn encrypt_char_pair(&self, c0: u8, c1: Option<u8>) -> [u8; N];
    fn decrypt_char_pair(&self, encrypted: [u8; N]) -> (u8, Option<u8>);

    fn encrypt<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        for byte_pair in BytePairs::new(reader) {
            let byte_pair = byte_pair?;
            let encrypted = self.encrypt_char_pair(byte_pair.0, byte_pair.1);
            writer.write_all(&encrypted)?;
        }
        Ok(())
    }

    fn decrypt<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        for encrypted in NBytes::new(reader) {
            match self.decrypt_char_pair(encrypted?) {
                (c0, Some(c1)) => writer.write_all(&[c0, c1]),
                (c0, None) => writer.write_all(&[c0]),
            }?;
        }
        Ok(())
    }
}
