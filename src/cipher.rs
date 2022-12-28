use anyhow::Result;
use std::string::FromUtf8Error;

const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;
const SINGLE_CHAR_MASK: u8 = 4;

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Result<String>;
    fn decrypt(&self, data: &[u8]) -> Result<String>;
}

pub struct Simple {}

impl Cipher for Simple {
    fn encrypt(&self, data: &[u8]) -> Result<String> {
        let mut result = new_encrypt_buffer(data);
        let mut iter = data.iter();
        loop {
            match (iter.next(), iter.next()) {
                (Some(c1), Some(c2)) => result.push_str(&Self::encrypt_char_pair(c1, c2)?),
                (Some(c1), None) => result.push_str(&Self::encrypt_single_char(c1)?),
                _ => return Ok(result),
            }
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<String> {
        let mut result = new_decrypt_buffer(data);
        let mut iter = data.iter();
        loop {
            match (iter.next(), iter.next(), iter.next()) {
                (Some(b1), Some(b2), Some(b3)) => {
                    result.push_str(&Self::decrypt_chars(b1, b2, b3)?)
                }
                _ => return Ok(result),
            }
        }
    }
}

impl Simple {
    fn encrypt_char_pair(c1: &u8, c2: &u8) -> Result<String, FromUtf8Error> {
        let high_1 = c1 & SIG_BIT_MASK;
        let high_2 = c2 & SIG_BIT_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        let low_2 = c2 & LOWER_BITS_MASK;
        let b1 = 224 | (high_1 >> 5) | (high_2 >> 6);
        let b2 = 128 | low_1;
        let b3 = 128 | low_2;
        // println!("Chars: {c1:b} {c2:b}");
        // println!("Bytes: {b1:b} {b2:b} {b3:b}");

        let encyrpted_char = vec![b1, b2, b3];
        String::from_utf8(encyrpted_char)
    }

    fn encrypt_single_char(c1: &u8) -> Result<String, FromUtf8Error> {
        let high_1 = c1 & SIG_BIT_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        let b1 = 224 | SINGLE_CHAR_MASK | (high_1 >> 6);
        let b2 = 128 | low_1;
        let b3 = 128;
        // println!("Chars: {c1:b}");
        // println!("Bytes: {b1:b} {b2:b} {b3:b}");

        let encyrpted_char = vec![b1, b2, b3];
        String::from_utf8(encyrpted_char)
    }

    fn decrypt_chars(b1: &u8, b2: &u8, b3: &u8) -> Result<String> {
        if b1 & SINGLE_CHAR_MASK != 0 {
            Self::decrypt_single_char(b1, b2)
        } else {
            Self::decrypt_char_pair(b1, b2, b3)
        }
    }

    fn decrypt_single_char(b1: &u8, b2: &u8) -> Result<String> {
        let sig_bit = (b1 & 1) << 6;
        let lower = b2 & LOWER_BITS_MASK;
        let ascii_char = sig_bit | lower;
        Ok(String::from_utf8(vec![ascii_char])?)
    }

    fn decrypt_char_pair(b1: &u8, b2: &u8, b3: &u8) -> Result<String> {
        let c1_sig_bit = (b1 & 2) << 5;
        let c2_sig_bit = (b1 & 1) << 6;
        let c1_lower = b2 & LOWER_BITS_MASK;
        let c2_lower = b3 & LOWER_BITS_MASK;

        let c1 = c1_sig_bit | c1_lower;
        let c2 = c2_sig_bit | c2_lower;
        Ok(String::from_utf8(vec![c1, c2])?)
    }
}

fn new_encrypt_buffer(data: &[u8]) -> String {
    let mut buffer = String::new();
    buffer.reserve(encrypt_size(data));
    return buffer;
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
        let res = cipher.encrypt("ad".as_bytes()).expect("must succeed");
        assert_eq!(res, "㡤");
        let decrypted = cipher.decrypt(res.as_bytes()).expect("must succeed");
        assert_eq!(decrypted, "ad");

        let res = cipher.encrypt("gc".as_bytes()).expect("must succeed");
        assert_eq!(res, "㧣");
        let decrypted = cipher.decrypt(res.as_bytes()).expect("must succeed");
        assert_eq!(decrypted, "gc");
    }

    #[test]
    fn even_length_string() {
        let cipher = Simple {};
        let res = cipher.encrypt("adgc".as_bytes()).expect("must succeed");
        assert_eq!(res, "㡤㧣");
        let decrypted = cipher.decrypt(res.as_bytes()).expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }
}
