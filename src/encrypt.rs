use crate::cipher::Cipher;
use anyhow::Result;
use std::io::{Cursor, Read, Write};

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

pub fn encrypt_string<C, const N: usize>(to_encrypt: &str, cipher: C) -> Result<String>
where
    C: Cipher<N>,
{
    let input = Cursor::new(to_encrypt);
    let buf_size = encrypt_size::<N>(to_encrypt.as_bytes().len());
    let mut result = Vec::with_capacity(buf_size);
    Encrypter::new(&mut result, cipher).encrypt(input)?;
    Ok(String::from_utf8(result)?)
}

fn encrypt_size<const N: usize>(num_bytes: usize) -> usize {
    let num_encrypted_chars_needed = if num_bytes % 2 == 0 {
        num_bytes / 2
    } else {
        (num_bytes / 2) + 1
    };
    return num_encrypted_chars_needed * N;
}
