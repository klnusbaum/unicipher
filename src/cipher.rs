use anyhow::Result;

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
                (Some(c0), Some(c1)) => result.push_str(&Self::encrypt_char_pair(c0, c1)?),
                (Some(c0), None) => result.push_str(&Self::encrypt_single_char(c0)?),
                _ => return Ok(result),
            }
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<String> {
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
}

impl Simple {
    fn encrypt_char_pair(c0: &u8, c1: &u8) -> Result<String> {
        let high_1 = c0 & SIG_BIT_MASK;
        let high_2 = c1 & SIG_BIT_MASK;
        let low_1 = c0 & LOWER_BITS_MASK;
        let low_2 = c1 & LOWER_BITS_MASK;
        let b0 = 224 | (high_1 >> 5) | (high_2 >> 6);
        let b1 = 128 | low_1;
        let b2 = 128 | low_2;
        // println!("Chars: {c0:b} {c1:b}");
        // println!("Bytes: {b0:b} {b1:b} {b2:b}");

        let encyrpted_char = vec![b0, b1, b2];
        Ok(String::from_utf8(encyrpted_char)?)
    }

    fn encrypt_single_char(c0: &u8) -> Result<String> {
        let high_1 = c0 & SIG_BIT_MASK;
        let low_1 = c0 & LOWER_BITS_MASK;
        let b0 = 224 | SINGLE_CHAR_MASK | (high_1 >> 6);
        let b1 = 128 | low_1;
        let b2 = 128;
        // println!("Chars: {c0:b}");
        // println!("Bytes: {b0:b} {b1:b} {b2:b}");

        let encyrpted_char = vec![b0, b1, b2];
        Ok(String::from_utf8(encyrpted_char)?)
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
