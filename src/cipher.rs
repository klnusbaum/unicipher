use std::io::{Cursor, Read, Write};

use anyhow::Result;

const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;
const SINGLE_CHAR_MASK: u8 = 4;

pub trait Cipher {
    fn encrypt_to_string(&self, data: &[u8]) -> Result<String>;
    fn decrypt_to_string(&self, data: &[u8]) -> Result<String>;
    fn encrypt(&self, data: &mut impl Read, out: &mut impl Write) -> Result<()>;
}

pub struct Simple {}

impl Cipher for Simple {
    fn encrypt_to_string(&self, data: &[u8]) -> Result<String> {
        let mut result = Vec::with_capacity(encrypt_size(&data));
        self.encrypt(&mut Cursor::new(data), &mut result)?;
        Ok(String::from_utf8(result)?)
    }

    fn decrypt_to_string(&self, data: &[u8]) -> Result<String> {
        let mut result = new_decrypt_buffer(data);
        let mut iter = data.iter();
        loop {
            match (iter.next(), iter.next(), iter.next()) {
                (Some(b0), Some(b1), Some(b2)) => {
                    result.push_str(&Self::decrypt_chars(b0, b1, b2)?)
                }
                _ => return Ok(result),
            }
        }
    }

    fn encrypt(&self, data: &mut impl Read, out: &mut impl Write) -> Result<()> {
        let ascii_chars = &mut [0, 0];
        loop {
            let n0 = data.read(&mut ascii_chars[0..1])?;
            let n1 = data.read(&mut ascii_chars[1..2])?;
            match (n0, n1) {
                (1, 1) => Self::encrypt_ascii_char_pair(ascii_chars[0], ascii_chars[1], out)?,
                (1, 0) => Self::encrypt_single_ascii_char(ascii_chars[0], out)?,
                _ => return Ok(()),
            };
        }
    }
}

impl Simple {
    fn encrypt_ascii_char_pair(c0: u8, c1: u8, out: &mut impl Write) -> Result<()> {
        let encrypted_char: &mut [u8] = &mut [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128 | low_1;
        // println!("Chars: {c0:b} {c1:b}");
        // println!("Bytes: {b0:b} {b1:b} {b2:b}");
        Ok(out.write_all(&encrypted_char)?)
    }

    fn encrypt_single_ascii_char(c0: u8, out: &mut impl Write) -> Result<()> {
        let encrypted_char: &mut [u8] = &mut [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128;
        // println!("Chars: {c0:b}");
        // println!("Bytes: {b0:b} {b1:b} {b2:b}");
        Ok(out.write_all(&encrypted_char)?)
    }

    fn decrypt_chars(b0: &u8, b1: &u8, b2: &u8) -> Result<String> {
        if b0 & SINGLE_CHAR_MASK != 0 {
            Self::decrypt_single_char(b0, b1)
        } else {
            Self::decrypt_char_pair(b0, b1, b2)
        }
    }

    fn decrypt_single_char(b0: &u8, b1: &u8) -> Result<String> {
        let sig_bit = (b0 & 1) << 6;
        let lower = b1 & LOWER_BITS_MASK;
        let ascii_char = sig_bit | lower;
        Ok(String::from_utf8(vec![ascii_char])?)
    }

    fn decrypt_char_pair(b0: &u8, b1: &u8, b2: &u8) -> Result<String> {
        let c0_sig_bit = (b0 & 2) << 5;
        let c1_sig_bit = (b0 & 1) << 6;
        let c0_lower = b1 & LOWER_BITS_MASK;
        let c1_lower = b2 & LOWER_BITS_MASK;

        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        Ok(String::from_utf8(vec![c0, c1])?)
    }
}

fn encrypt_size(data: &[u8]) -> usize {
    let num_chars_needed = if data.len() % 2 == 0 {
        data.len() / 2
    } else {
        (data.len() / 2) + 1
    };

    return num_chars_needed * 3;
}

fn new_decrypt_buffer(data: &[u8]) -> String {
    let mut buffer = String::new();
    buffer.reserve(decrypt_size(data));
    return buffer;
}

fn decrypt_size(data: &[u8]) -> usize {
    let num_encrypted_chars = data.len() / 3;
    let num_decrypted_chars = num_encrypted_chars / 2;
    return num_decrypted_chars;
}

#[cfg(test)]
mod simple_tests {
    use super::{Cipher, Simple};

    #[test]
    fn single_char_pair() {
        let cipher = Simple {};
        let res = cipher
            .encrypt_to_string("ad".as_bytes())
            .expect("must succeed");
        assert_eq!(res, "㡤");
        let decrypted = cipher
            .decrypt_to_string(res.as_bytes())
            .expect("must succeed");
        assert_eq!(decrypted, "ad");

        let res = cipher
            .encrypt_to_string("gc".as_bytes())
            .expect("must succeed");
        assert_eq!(res, "㧣");
        let decrypted = cipher
            .decrypt_to_string(res.as_bytes())
            .expect("must succeed");
        assert_eq!(decrypted, "gc");
    }

    #[test]
    fn even_length_string() {
        let cipher = Simple {};
        let res = cipher
            .encrypt_to_string("adgc".as_bytes())
            .expect("must succeed");
        assert_eq!(res, "㡤㧣");
        let decrypted = cipher
            .decrypt_to_string(res.as_bytes())
            .expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }
}
