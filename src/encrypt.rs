use crate::cipher::Algorithm;
use anyhow::Result;
use std::io::{Cursor, Read, Write};

pub struct Encrypter<W, A, const N: usize> {
    to: W,
    algorithm: A,
}

impl<W: Write, A: Algorithm<N>, const N: usize> Encrypter<W, A, N> {
    pub fn new(to: W, algorithm: A) -> Self {
        Encrypter { to, algorithm }
    }

    pub fn encrypt<R>(&mut self, from: R) -> Result<()>
    where
        R: Read,
    {
        let mut bytes = from.bytes();
        loop {
            let encrypted = match (bytes.next(), bytes.next()) {
                (Some(c0), Some(c1)) => self.algorithm.encrypt_char_pair(c0?, c1?),
                (Some(c0), None) => self.algorithm.encrypt_single_char(c0?),
                _ => return Ok(()),
            };
            self.to.write_all(&encrypted)?;
        }
    }
}

pub fn encrypt_string<A, const N: usize>(to_encrypt: &str, algorithm: A) -> Result<String>
where
    A: Algorithm<N>,
{
    let input = Cursor::new(to_encrypt);
    let buf_size = encrypt_size::<N>(to_encrypt.as_bytes().len());
    let mut result = Vec::with_capacity(buf_size);
    Encrypter::new(&mut result, algorithm).encrypt(input)?;
    Ok(String::from_utf8(result)?)
}

const fn encrypt_size<const N: usize>(num_bytes: usize) -> usize {
    let num_encrypted_chars_needed = if num_bytes % 2 == 0 {
        num_bytes / 2
    } else {
        (num_bytes / 2) + 1
    };
    return num_encrypted_chars_needed * N;
}
