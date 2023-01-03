use crate::cipher::Cipher;
use anyhow::Result;
use std::io::{Bytes, Read, Write};
use std::iter::Fuse;

pub struct Encrypter<W, C, const N: usize> {
    writer: W,
    cipher: C,
}

impl<W: Write, C: Cipher<N>, const N: usize> Encrypter<W, C, N> {
    pub fn new(writer: W, cipher: C) -> Self {
        Encrypter { writer, cipher }
    }

    pub fn encrypt<R>(&mut self, reader: R) -> Result<()>
    where
        R: Read,
    {
        for byte_pair in BytePairs::new(reader) {
            let encrypted = match byte_pair {
                (c0, Some(c1)) => self.cipher.encrypt_char_pair(c0?, c1?),
                (c0, None) => self.cipher.encrypt_char(c0?),
            };
            self.writer.write_all(&encrypted)?;
        }
        Ok(())
    }
}

struct BytePairs<R> {
    bytes: Fuse<Bytes<R>>,
}

impl<R: Read> BytePairs<R> {
    fn new(reader: R) -> Self {
        BytePairs {
            // N.B. Bytes can theoretically return a Some after having returned a None.
            // This is a general property of iterators, but is of specific concern for Bytes.
            // The underlying reader may return 0 on a read call,
            // but then start returning data again.
            // This would screw up our pair logic, which can't handle when the first
            // byte is None, but the second byte is Some.
            // (a BytePair always needs a first byte, only the second byte it optional).
            //
            // We use a Fuse so that as soon as we see a None from the Bytes iterator,
            // we consider ourself to be done.
            bytes: reader.bytes().fuse(),
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
