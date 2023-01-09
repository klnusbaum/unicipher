mod bytepairs;
mod chars;
mod simple;
#[cfg(test)]
mod tests;

use anyhow::Result;
use bytepairs::BytePairs;
use chars::Chars;
use std::io::{Read, Write};

pub use simple::Simple;

pub type BytePair = (u8, u8);

/**
 * CipherV2 provides several major enhancements over the initial verison of Cipher:
 *   - We don't concern ourselves with odd length strings. We just assume two chars always and
 *   0-pad where necessary (and ignore the 0-pad where necessary).
 *   - Encryption and Decryption targets are an actual char. This helps us ensure we're always
 *   encrypting to a valid unicode point, as well as allowing us to write more straight forward
 *   ciphers. We think about the code point we're encrypting/decrypting to/from rather than
 *   thinking about the structure of utf-8 encoding.
 */
pub trait CipherV2 {
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
