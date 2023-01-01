use super::{Decrypt, Encrypt};
use anyhow::Result;
use std::io::{Cursor, Read, Write};

const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;
const SINGLE_CHAR_MASK: u8 = 4;

pub struct Encrypter<W: Write> {
    writer: W,
}

impl<W: Write> Encrypter<W> {
    pub fn new(writer: W) -> Self {
        Encrypter { writer }
    }

    fn encrypt_ascii_char_pair(&mut self, c0: u8, c1: u8) -> Result<()> {
        let encrypted_char = &mut [0, 0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 240;
        encrypted_char[1] = 144 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[2] = 128 | low_0;
        encrypted_char[3] = 128 | low_1;
        Ok(self.writer.write_all(encrypted_char)?)
    }

    fn encrypt_single_ascii_char(&mut self, c0: u8) -> Result<()> {
        let encrypted_char = &mut [0, 0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 240;
        encrypted_char[1] = 144 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[2] = 128 | low_0;
        encrypted_char[3] = 128;
        Ok(self.writer.write_all(encrypted_char)?)
    }
}

impl<W: Write> super::Encrypt for Encrypter<W> {
    fn encrypt<R: Read>(&mut self, data: R) -> Result<()> {
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

pub struct Decrypter<W: Write> {
    writer: W,
}

impl<W: Write> Decrypter<W> {
    pub fn new(writer: W) -> Self {
        Decrypter { writer }
    }

    fn decrypt_chars(&mut self, b0: u8, b1: u8, b2: u8, b3: u8) -> Result<()> {
        if b1 & SINGLE_CHAR_MASK != 0 {
            self.decrypt_single_char(b1, b2)
        } else {
            self.decrypt_char_pair(b1, b2, b3)
        }
    }

    fn decrypt_single_char(&mut self, b1: u8, b2: u8) -> Result<()> {
        let sig_bit = (b1 & 1) << 6;
        let lower = b2 & LOWER_BITS_MASK;
        let ascii_char = [sig_bit | lower];
        Ok(self.writer.write_all(&ascii_char)?)
    }

    fn decrypt_char_pair(&mut self, b1: u8, b2: u8, b3: u8) -> Result<()> {
        let c0_sig_bit = (b1 & 2) << 5;
        let c1_sig_bit = (b1 & 1) << 6;
        let c0_lower = b2 & LOWER_BITS_MASK;
        let c1_lower = b3 & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        let ascii_chars = [c0, c1];
        Ok(self.writer.write_all(&ascii_chars)?)
    }
}

impl<W: Write> super::Decrypt for Decrypter<W> {
    fn decrypt<R: Read>(&mut self, data: R) -> Result<()> {
        let mut bytes = data.bytes();
        loop {
            match (bytes.next(), bytes.next(), bytes.next(), bytes.next()) {
                (Some(b0), Some(b1), Some(b2), Some(b3)) => {
                    self.decrypt_chars(b0?, b1?, b2?, b3?)?
                }
                _ => return Ok(()),
            };
        }
    }
}

pub fn encrypt_string(data: &str) -> Result<String> {
    let input = Cursor::new(data);
    let mut result = Vec::with_capacity(encrypt_size(data.as_bytes()));
    let mut encrypter = Encrypter::new(&mut result);
    encrypter.encrypt(input)?;
    Ok(String::from_utf8(result)?)
}

pub fn decrypt_string(data: &str) -> Result<String> {
    let input = Cursor::new(data);
    let mut result = Vec::with_capacity(decrypt_size(data.as_bytes()));
    let mut decrypter = Decrypter::new(&mut result);
    decrypter.decrypt(input)?;
    Ok(String::from_utf8(result)?)
}

fn encrypt_size(data: &[u8]) -> usize {
    let num_encrypted_chars_needed = if data.len() % 2 == 0 {
        data.len() / 2
    } else {
        (data.len() / 2) + 1
    };
    return num_encrypted_chars_needed * 4;
}

fn decrypt_size(data: &[u8]) -> usize {
    let num_encrypted_chars = data.len() / 4;
    return num_encrypted_chars * 2;
}

#[cfg(test)]
mod extended_tests {
    use super::{decrypt_string, encrypt_string};

    #[test]
    fn single_char_pair() {
        // a = 97
        // d = 100
        // a = 01100001
        // d = 01100100
        // a sig = 1
        // d sig = 1
        // a lower = 100001
        // d lower = 100100
        // b0 = 1111000
        // b1 = 10010011
        // b2 = 10100001
        // b3 = 10100100
        // code point = 0 0001 0011 1000 0110 0100
        // code point =   1    3    8    6    4
        let res = encrypt_string("ad").expect("must succeed");
        assert_eq!(res, "\u{13864}");
        let decrypted = decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "ad");
    }

    #[test]
    fn even_length_string() {
        let res = encrypt_string("adgc").expect("must succeed");
        assert_eq!(res, "\u{13864}\u{139e3}");
        let decrypted = decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }

    #[test]
    fn odd_length_string() {
        // b = 98
        // b = 98
        // b = 01100010
        // b = 01100010
        // b sig = 1
        // b sig = 1
        // b lower = 100010
        // b lower = 100010
        // b0 = 1111000
        // b1 = 10010011
        // b2 = 10100010
        // b3 = 10100010
        // code point = 0 0001 0011 1000 1010 0010
        // code point =   1    3    8    a    2
        //
        // b = 98
        // b = 01100010
        // b sig = 1
        // b lower = 100010
        // b0 = 11110000
        // b1 = 10010101
        // b2 = 10100010
        // b3 = 10000000
        // code point = 0 0001 0101 1000 1000 0000
        // code point =   1    5    8    8    0
        let res = encrypt_string("bbb").expect("must succeed");
        assert_eq!(res, "\u{138a2}\u{15880}");
        let decrypted = decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "bbb");
    }

    #[test]
    fn single_char_string() {
        let res = encrypt_string("x").expect("must succeed");
        assert_eq!(res, "\u{15e00}");
        let decrypted = decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "x");
    }
}
