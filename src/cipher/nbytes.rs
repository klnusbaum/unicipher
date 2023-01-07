use anyhow::{Error, Result};
use std::io::{Bytes, Read};

pub struct NBytes<R: Read, const N: usize> {
    bytes: Bytes<R>,
}

impl<R: Read, const N: usize> NBytes<R, N> {
    pub fn new(reader: R) -> NBytes<R, N> {
        NBytes {
            bytes: reader.bytes(),
        }
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
                None => return Some(insufficent_bytes(i)),
            }
        }
        Some(Ok(encrypted))
    }
}

fn insufficent_bytes<const N: usize>(num_bytes: usize) -> Result<[u8; N]> {
    Err(Error::msg(format!(
        "expected utf-8 character of {} bytes but found character with only {} byte(s)",
        N, num_bytes
    )))
}
