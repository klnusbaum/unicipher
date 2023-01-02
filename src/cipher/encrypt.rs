use crate::cipher::Cipher;
use anyhow::Result;
use std::io::{Read, Write};

pub struct Encrypter<W, C, const N: usize> {
    to: W,
    cipher: C,
}

impl<W: Write, C: Cipher<N>, const N: usize> Encrypter<W, C, N> {
    pub fn new(to: W, cipher: C) -> Self {
        Encrypter { to, cipher }
    }

    pub fn encrypt<R>(&mut self, from: R) -> Result<()>
    where
        R: Read,
    {
        let mut bytes = from.bytes();
        loop {
            let encrypted = match (bytes.next(), bytes.next()) {
                (Some(c0), Some(c1)) => self.cipher.encrypt_char_pair(c0?, c1?),
                (Some(c0), None) => self.cipher.encrypt_single_char(c0?),
                _ => return Ok(()),
            };
            self.to.write_all(&encrypted)?;
        }
    }
}
