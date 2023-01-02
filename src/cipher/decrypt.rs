use crate::cipher::Cipher;
use anyhow::{Error, Result};
use std::io::{Bytes, Read, Write};

pub struct Decrypter<W, C, const N: usize> {
    writer: W,
    cipher: C,
}

impl<W: Write, C: Cipher<N>, const N: usize> Decrypter<W, C, N> {
    pub fn new(writer: W, cipher: C) -> Self {
        Decrypter { writer, cipher }
    }

    pub fn decrypt<R>(&mut self, reader: R) -> Result<()>
    where
        R: Read,
    {
        for encrypted in NBytes::new(reader.bytes()) {
            let encrypted = encrypted?;
            if self.cipher.has_single_char(encrypted) {
                let bytes = self.cipher.decrypt_char(encrypted);
                self.writer.write_all(&bytes)?;
            } else {
                let bytes = self.cipher.decrypt_char_pair(encrypted);
                self.writer.write_all(&bytes)?;
            };
        }
        Ok(())
    }
}

struct NBytes<R: Read, const N: usize> {
    inner: Bytes<R>,
}

impl<R: Read, const N: usize> NBytes<R, N> {
    fn new(inner: Bytes<R>) -> NBytes<R, N> {
        NBytes { inner }
    }

    fn insufficent_bytes(num_bytes: usize) -> Result<[u8; N]> {
        Err(Error::msg(format!(
            "expected utf-8 character of {} bytes but found character with only {} byte(s)",
            N, num_bytes
        )))
    }
}

impl<R: Read, const N: usize> Iterator for NBytes<R, N> {
    type Item = Result<[u8; N]>;

    fn next(&mut self) -> Option<Result<[u8; N]>> {
        let mut encrypted = [0; N];
        for i in 0..N {
            match self.inner.next() {
                Some(Ok(byte)) => encrypted[i] = byte,
                None if i == 0 => return None,
                Some(Err(e)) => return Some(Err(Error::new(e))),
                None => return Some(Self::insufficent_bytes(i)),
            }
        }
        Some(Ok(encrypted))
    }
}
