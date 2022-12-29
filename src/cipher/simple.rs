use super::{Decrypt, Encrypt};
use anyhow::Result;
use std::io::{Cursor, Read, Write};

const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;
const SINGLE_CHAR_MASK: u8 = 4;

pub struct Encrypter<W: Write> {
    out: W,
}

impl<W: Write> From<W> for Encrypter<W> {
    fn from(out: W) -> Self {
        Encrypter { out }
    }
}

impl<W: Write> Encrypt for Encrypter<W> {
    fn encrypt(&mut self, data: impl Read) -> Result<()> {
        let mut bytes = data.bytes();
        loop {
            match (bytes.next(), bytes.next()) {
                (Some(c0), Some(c1)) => self.encrypt_ascii_char_pair(c0?, c1?)?,
                (Some(c0), None) => self.encrypt_single_ascii_char(c0?)?,
                _ => return Ok(()),
            };
        }
    }
}

impl<W: Write> Encrypter<W> {
    fn encrypt_ascii_char_pair(&mut self, c0: u8, c1: u8) -> Result<()> {
        let encrypted_char = &mut [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128 | low_1;
        Ok(self.out.write_all(encrypted_char)?)
    }

    fn encrypt_single_ascii_char(&mut self, c0: u8) -> Result<()> {
        let encrypted_char = &mut [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128;
        Ok(self.out.write_all(encrypted_char)?)
    }
}

pub struct Decrypter<W: Write> {
    out: W,
}

impl<W: Write> From<W> for Decrypter<W> {
    fn from(out: W) -> Self {
        Decrypter { out }
    }
}

impl<W: Write> Decrypt for Decrypter<W> {
    fn decrypt(&mut self, data: impl Read) -> Result<()> {
        let mut bytes = data.bytes();
        loop {
            match (bytes.next(), bytes.next(), bytes.next()) {
                (Some(b0), Some(b1), Some(b2)) => self.decrypt_chars2(b0?, b1?, b2?)?,
                _ => return Ok(()),
            };
        }
    }
}

impl<W: Write> Decrypter<W> {
    fn decrypt_chars2(&mut self, b0: u8, b1: u8, b2: u8) -> Result<()> {
        if b0 & SINGLE_CHAR_MASK != 0 {
            self.decrypt_single_char2(b0, b1)
        } else {
            self.decrypt_char_pair2(b0, b1, b2)
        }
    }

    fn decrypt_single_char2(&mut self, b0: u8, b1: u8) -> Result<()> {
        let sig_bit = (b0 & 1) << 6;
        let lower = b1 & LOWER_BITS_MASK;
        let ascii_char = [sig_bit | lower];
        Ok(self.out.write_all(&ascii_char)?)
    }

    fn decrypt_char_pair2(&mut self, b0: u8, b1: u8, b2: u8) -> Result<()> {
        let c0_sig_bit = (b0 & 2) << 5;
        let c1_sig_bit = (b0 & 1) << 6;
        let c0_lower = b1 & LOWER_BITS_MASK;
        let c1_lower = b2 & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        let ascii_chars = [c0, c1];
        Ok(self.out.write_all(&ascii_chars)?)
    }
}

pub fn encrypt_to_string(data: &[u8]) -> Result<String> {
    let mut result = Vec::with_capacity(encrypt_size(&data));
    let mut encrypter = Encrypter::from(&mut result);
    encrypter.encrypt(&mut Cursor::new(data))?;
    Ok(String::from_utf8(result)?)
}

pub fn decrypt_to_string(data: &[u8]) -> Result<String> {
    let mut result = Vec::with_capacity(decrypt_size(&data));
    let mut decrypter = Decrypter::from(&mut result);
    decrypter.decrypt(&mut Cursor::new(data))?;
    Ok(String::from_utf8(result)?)
}

fn encrypt_size(data: &[u8]) -> usize {
    let num_chars_needed = if data.len() % 2 == 0 {
        data.len() / 2
    } else {
        (data.len() / 2) + 1
    };

    return num_chars_needed * 3;
}

fn decrypt_size(data: &[u8]) -> usize {
    let num_encrypted_chars = data.len() / 3;
    let num_decrypted_chars = num_encrypted_chars / 2;
    return num_decrypted_chars;
}

#[cfg(test)]
mod simple_tests {

    #[test]
    fn single_char_pair() {
        let res = super::encrypt_to_string("ad".as_bytes()).expect("must succeed");
        assert_eq!(res, "㡤");
        let decrypted = super::decrypt_to_string(res.as_bytes()).expect("must succeed");
        assert_eq!(decrypted, "ad");

        let res = super::encrypt_to_string("gc".as_bytes()).expect("must succeed");
        assert_eq!(res, "㧣");
        let decrypted = super::decrypt_to_string(res.as_bytes()).expect("must succeed");
        assert_eq!(decrypted, "gc");
    }

    #[test]
    fn even_length_string() {
        let res = super::encrypt_to_string("adgc".as_bytes()).expect("must succeed");
        assert_eq!(res, "㡤㧣");
        let decrypted = super::decrypt_to_string(res.as_bytes()).expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }
}
