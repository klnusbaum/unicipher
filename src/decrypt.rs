use crate::cipher::Cipher;
use anyhow::{Error, Result};
use std::io::{Bytes, Cursor, Read, Write};

pub struct Decrypter<W, C, const N: usize> {
    to: W,
    cipher: C,
}

impl<W: Write, C: Cipher<N>, const N: usize> Decrypter<W, C, N> {
    pub fn new(to: W, cipher: C) -> Self {
        Decrypter { to, cipher }
    }

    pub fn decrypt<R>(&mut self, from: R) -> Result<()>
    where
        R: Read,
    {
        for encrypted in NBytes::new(from.bytes()) {
            let encrypted = encrypted?;
            if self.cipher.has_single_char(encrypted) {
                self.to
                    .write_all(&self.cipher.decrypt_single_char(encrypted))
            } else {
                self.to.write_all(&self.cipher.decrypt_char_pair(encrypted))
            }?;
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

pub fn decrypt_string<C, const N: usize>(to_decrypt: &str, cipher: C) -> Result<String>
where
    C: Cipher<N>,
{
    let input = Cursor::new(to_decrypt);
    let buf_size = decrypt_size::<N>(to_decrypt.as_bytes().len());
    let mut result = Vec::with_capacity(buf_size);
    Decrypter::new(&mut result, cipher).decrypt(input)?;
    Ok(String::from_utf8(result)?)
}

fn decrypt_size<const N: usize>(num_bytes: usize) -> usize {
    let num_encrypted_chars = num_bytes / N;
    return num_encrypted_chars * 2;
}
