use crate::cipher::Cipher;
use anyhow::Result;
use std::io::{Bytes, Read, Write};
use std::iter::Fuse;

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
        for byte_pair in BytePairs::new(from.bytes()) {
            let encrypted = match byte_pair {
                (c0, Some(c1)) => self.cipher.encrypt_char_pair(c0?, c1?),
                (c0, None) => self.cipher.encrypt_single_char(c0?),
            };
            self.to.write_all(&encrypted)?;
        }
        Ok(())
    }
}

struct BytePairs<R> {
    bytes: Fuse<Bytes<R>>,
}

impl<R: Read> BytePairs<R> {
    fn new(bytes: Bytes<R>) -> Self {
        BytePairs {
            bytes: bytes.fuse(),
        }
    }
}

impl<R: Read> Iterator for BytePairs<R> {
    type Item = BytePair;

    fn next(&mut self) -> Option<BytePair> {
        match (self.bytes.next(), self.bytes.next()) {
            (Some(b0), Some(b1)) => Some((b0, Some(b1))),
            (Some(b0), None) => Some((b0, None)),
            _ => None,
        }
    }
}

type BytePair = (std::io::Result<u8>, Option<std::io::Result<u8>>);
