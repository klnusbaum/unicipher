mod bytepairs;
mod chars;

use anyhow::Result;
use bytepairs::BytePairs;
use chars::Chars;
use std::io::{Read, Write};

pub type BytePair = (u8, u8);

pub trait Cipher<const N: usize> {
    fn encrypt_char_pair(&self, pair: BytePair) -> char;
    fn decrypt_char_pair(&self, encrypted: char) -> BytePair;

    fn encrypt<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut buf = [0, 0, 0, 0];
        for byte_pair in BytePairs::new(reader) {
            let encrypted = self.encrypt_char_pair(byte_pair?);
            let encoded = encrypted.encode_utf8(&mut buf);
            writer.write_all(&encoded.as_bytes())?;
        }
        Ok(())
    }

    fn decrypt<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        for encrypted in Chars::new(reader) {
            match self.decrypt_char_pair(encrypted?) {
                (c0, c1) if c1 == 0 => writer.write_all(&[c0]),
                (c0, c1) => writer.write_all(&[c0, c1]),
            }?;
        }
        Ok(())
    }
}
