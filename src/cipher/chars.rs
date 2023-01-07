use anyhow::{Error, Result};
use std::io::{ErrorKind, Read};
use std::str::{from_utf8, FromStr};

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
