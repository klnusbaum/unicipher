use anyhow::{Error, Result};
use std::io::{Bytes, Cursor, Read, Write};

pub mod extended;
pub mod standard;

pub trait Encrypt {
    fn encrypt<R: Read>(&mut self, data: R) -> Result<()>;
}

pub trait Decrypt {
    fn decrypt<R: Read>(&mut self, data: R) -> Result<()>;
}

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
