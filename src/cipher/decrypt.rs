use crate::cipher::Cipher;
use anyhow::{Error, Result};
use std::io::{Bytes, ErrorKind, Read, Write};
use std::str::{from_utf8, FromStr};

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
        for encrypted in NBytes::new(reader) {
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
    bytes: Bytes<R>,
}

impl<R: Read, const N: usize> NBytes<R, N> {
    fn new(reader: R) -> NBytes<R, N> {
        NBytes {
            bytes: reader.bytes(),
        }
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
            match self.bytes.next() {
                Some(Ok(byte)) => encrypted[i] = byte,
                None if i == 0 => return None,
                Some(Err(e)) => return Some(Err(Error::new(e))),
                None => return Some(Self::insufficent_bytes(i)),
            }
        }
        Some(Ok(encrypted))
    }
}

pub struct Chars<R: Read> {
    reader: R,
}

impl<R: Read> Chars<R> {
    pub fn new(reader: R) -> Self {
        Chars { reader }
    }

    fn next_char(&mut self) -> Result<Option<char>> {
        let mut buf = [0, 0, 0, 0];
        if self.read_char_len(&mut buf)? == 0 {
            return Ok(None);
        }

        let char_len = char_len(buf[0])?;
        if char_len > 1 {
            self.reader.read_exact(&mut buf[1..char_len])?;
        }

        let decoded_char = char::from_str(from_utf8(&buf[0..char_len])?)?;
        Ok(Some(decoded_char))
    }

    fn read_char_len(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match self.reader.read(&mut buf[0..1]) {
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                res => return Ok(res?),
            }
        }
    }
}

impl<R: Read> Iterator for Chars<R> {
    type Item = Result<char>;

    fn next(&mut self) -> Option<Result<char>> {
        self.next_char().transpose()
    }
}

fn char_len(first_byte: u8) -> Result<usize> {
    match first_byte {
        0b0000_0000..=0b0111_0000 => Ok(1),
        0b1000_0000..=0b1101_1111 => Ok(2),
        0b1110_0000..=0b1110_1111 => Ok(3),
        0b1111_0000..=0b1111_0111 => Ok(4),
        _ => Err(Error::msg(format!("invalid first byte: {}", first_byte))),
    }
}

#[cfg(test)]
mod tests {
    use super::Chars;
    use std::io::Cursor;

    #[test]
    fn char_test() {
        let reader = Cursor::new("h💯❤⭐k".to_string());
        let mut chars = Chars::new(reader);
        let res = chars.next().unwrap().expect("got error");
        assert_eq!('h', res);
        let res = chars.next().unwrap().expect("got error");
        assert_eq!('💯', res);
        let res = chars.next().unwrap().expect("got error");
        assert_eq!('❤', res);
        let res = chars.next().unwrap().expect("got error");
        assert_eq!('⭐', res);
        let res = chars.next().unwrap().expect("got error");
        assert_eq!('k', res);
    }
}
