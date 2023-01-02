use anyhow::{Error, Result};
use std::io::{Bytes, Cursor, Read, Write};

const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;
const SINGLE_CHAR_MASK: u8 = 4;

pub trait Algorithm<const N: usize> {
    fn encrypt_chars(&self, c0: u8, c1: Option<u8>) -> [u8; N];
    fn decrypt_chars(&self, encrypted: [u8; N]) -> (u8, Option<u8>);
}

pub struct Cipher<A: Algorithm<N>, const N: usize> {
    algorithm: A,
}

impl<A: Algorithm<N>, const N: usize> Cipher<A, N> {
    pub fn new(algorithm: A) -> Self {
        Cipher { algorithm }
    }

    pub fn encrypt<R, W>(&self, from: R, mut to: W) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut bytes = from.bytes();
        loop {
            let encrypted = match (bytes.next(), bytes.next()) {
                (Some(c0), Some(c1)) => self.algorithm.encrypt_chars(c0?, Some(c1?)),
                (Some(c0), None) => self.algorithm.encrypt_chars(c0?, None),
                _ => return Ok(()),
            };
            to.write_all(&encrypted)?;
        }
    }

    pub fn decrypt<R, W>(&self, from: R, mut to: W) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut bytes = from.bytes();
        loop {
            let encrypted = match Self::read_n_bytes(&mut bytes)? {
                Some(e) => e,
                None => return Ok(()),
            };
            match self.algorithm.decrypt_chars(encrypted) {
                (c0, Some(c1)) => to.write_all(&[c0, c1])?,
                (c0, None) => to.write_all(&[c0])?,
            }
        }
    }

    fn read_n_bytes<R: Read>(from: &mut Bytes<R>) -> Result<Option<[u8; N]>> {
        let mut encrypted = [0; N];
        for i in 0..N {
            match from.next() {
                Some(byte) => encrypted[i] = byte?,
                None if i == 0 => return Ok(None),
                None => return Self::insufficent_bytes(i),
            }
        }
        Ok(Some(encrypted))
    }

    fn insufficent_bytes(num_bytes: usize) -> Result<Option<[u8; N]>> {
        Err(Error::msg(format!(
            "expected utf-8 character of {} bytes but found character with only {} byte(s)",
            N, num_bytes
        )))
    }

    pub fn encrypt_string(&self, to_encrypt: &str) -> Result<String> {
        let input = Cursor::new(to_encrypt);
        let buf_size = Self::encrypt_size(to_encrypt.as_bytes().len());
        let mut result = Vec::with_capacity(buf_size);
        self.encrypt(input, &mut result)?;
        Ok(String::from_utf8(result)?)
    }

    pub fn decrypt_string(&self, to_decrypt: &str) -> Result<String> {
        let input = Cursor::new(to_decrypt);
        let buf_size = Self::decrypt_size(to_decrypt.as_bytes().len());
        let mut result = Vec::with_capacity(buf_size);
        self.decrypt(input, &mut result)?;
        Ok(String::from_utf8(result)?)
    }

    const fn encrypt_size(num_bytes: usize) -> usize {
        let num_encrypted_chars_needed = if num_bytes % 2 == 0 {
            num_bytes / 2
        } else {
            (num_bytes / 2) + 1
        };
        return num_encrypted_chars_needed * N;
    }

    const fn decrypt_size(num_bytes: usize) -> usize {
        let num_encrypted_chars = num_bytes / N;
        return num_encrypted_chars * 2;
    }
}

pub struct Standard {}

impl Standard {
    fn encrypt_char_pair(c0: u8, c1: u8) -> [u8; 3] {
        let mut encrypted_char = [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128 | low_1;
        return encrypted_char;
    }

    fn encrypt_single_char(c0: u8) -> [u8; 3] {
        let mut encrypted_char = [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128;
        return encrypted_char;
    }

    fn decrypt_single_char(encrypted: [u8; 3]) -> u8 {
        let sig_bit = (encrypted[0] & 1) << 6;
        let lower = encrypted[1] & LOWER_BITS_MASK;
        return sig_bit | lower;
    }

    fn decrypt_char_pair(encrypted: [u8; 3]) -> (u8, u8) {
        let c0_sig_bit = (encrypted[0] & 2) << 5;
        let c1_sig_bit = (encrypted[0] & 1) << 6;
        let c0_lower = encrypted[1] & LOWER_BITS_MASK;
        let c1_lower = encrypted[2] & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        return (c0, c1);
    }
}

impl Algorithm<3> for Standard {
    fn encrypt_chars(&self, c0: u8, c1: Option<u8>) -> [u8; 3] {
        match c1 {
            Some(c1) => Self::encrypt_char_pair(c0, c1),
            None => Self::encrypt_single_char(c0),
        }
    }

    fn decrypt_chars(&self, encrypted: [u8; 3]) -> (u8, Option<u8>) {
        if encrypted[0] & SINGLE_CHAR_MASK != 0 {
            (Self::decrypt_single_char(encrypted), None)
        } else {
            let (c0, c1) = Self::decrypt_char_pair(encrypted);
            (c0, Some(c1))
        }
    }
}

pub struct Extended {}

impl Extended {
    fn encrypt_char_pair(c0: u8, c1: u8) -> [u8; 4] {
        let mut encrypted_char = [0, 0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 240;
        encrypted_char[1] = 144 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[2] = 128 | low_0;
        encrypted_char[3] = 128 | low_1;
        return encrypted_char;
    }

    fn encrypt_single_char(c0: u8) -> [u8; 4] {
        let mut encrypted_char = [0, 0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 240;
        encrypted_char[1] = 144 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[2] = 128 | low_0;
        encrypted_char[3] = 128;
        return encrypted_char;
    }

    fn decrypt_single_char(encrypted: [u8; 4]) -> u8 {
        let sig_bit = (encrypted[1] & 1) << 6;
        let lower = encrypted[2] & LOWER_BITS_MASK;
        return sig_bit | lower;
    }

    fn decrypt_char_pair(encrypted: [u8; 4]) -> (u8, u8) {
        let c0_sig_bit = (encrypted[1] & 2) << 5;
        let c1_sig_bit = (encrypted[1] & 1) << 6;
        let c0_lower = encrypted[2] & LOWER_BITS_MASK;
        let c1_lower = encrypted[3] & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        return (c0, c1);
    }
}

impl Algorithm<4> for Extended {
    fn encrypt_chars(&self, c0: u8, c1: Option<u8>) -> [u8; 4] {
        match c1 {
            Some(c1) => Self::encrypt_char_pair(c0, c1),
            None => Self::encrypt_single_char(c0),
        }
    }

    fn decrypt_chars(&self, encrypted: [u8; 4]) -> (u8, Option<u8>) {
        if encrypted[1] & SINGLE_CHAR_MASK != 0 {
            (Self::decrypt_single_char(encrypted), None)
        } else {
            let (c0, c1) = Self::decrypt_char_pair(encrypted);
            (c0, Some(c1))
        }
    }
}

#[cfg(test)]
mod standard_tests {
    use super::{Cipher, Standard};

    #[test]
    fn single_char_pair() {
        let cipher = Cipher::new(Standard {});
        let res = cipher.encrypt_string("ad").expect("must succeed");
        assert_eq!(res, "㡤");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "ad");
    }

    #[test]
    fn even_length_string() {
        let cipher = Cipher::new(Standard {});
        let res = cipher.encrypt_string("adgc").expect("must succeed");
        assert_eq!(&res, "㡤㧣");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }

    #[test]
    fn odd_length_string() {
        let cipher = Cipher::new(Standard {});
        let res = cipher.encrypt_string("bbb").expect("must succeed");
        assert_eq!(&res, "㢢墀");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "bbb");
    }

    #[test]
    fn single_char_string() {
        let cipher = Cipher::new(Standard {});
        let res = cipher.encrypt_string("x").expect("must succeed");
        assert_eq!(&res, "帀");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "x");
    }
}

#[cfg(test)]
mod extended_tests {
    use super::{Cipher, Extended};

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
        let cipher = Cipher::new(Extended {});
        let res = cipher.encrypt_string("ad").expect("must succeed");
        assert_eq!(res, "\u{13864}");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "ad");
    }

    #[test]
    fn even_length_string() {
        let cipher = Cipher::new(Extended {});
        let res = cipher.encrypt_string("adgc").expect("must succeed");
        assert_eq!(res, "\u{13864}\u{139e3}");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
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
        let cipher = Cipher::new(Extended {});
        let res = cipher.encrypt_string("bbb").expect("must succeed");
        assert_eq!(res, "\u{138a2}\u{15880}");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "bbb");
    }

    #[test]
    fn single_char_string() {
        let cipher = Cipher::new(Extended {});
        let res = cipher.encrypt_string("x").expect("must succeed");
        assert_eq!(res, "\u{15e00}");
        let decrypted = cipher.decrypt_string(&res).expect("must succeed");
        assert_eq!(decrypted, "x");
    }
}
