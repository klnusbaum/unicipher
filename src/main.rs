use anyhow::Result;
use std::string::FromUtf8Error;

const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;

fn main() -> Result<()> {
    println!(
        "Encrytped char is: '{}{}'",
        encrypt_char_pair(&b'a', &b'd')?,
        encrypt_char_pair(&b'g', &b'c')?
    );
    Ok(())
}

fn encrypt_char_pair(c1: &u8, c2: &u8) -> Result<String, FromUtf8Error> {
    let high_1 = c1 & SIG_BIT_MASK;
    let high_2 = c2 & SIG_BIT_MASK;
    let low_1 = c1 & LOWER_BITS_MASK;
    let low_2 = c2 & LOWER_BITS_MASK;
    let b1 = 224 | (high_1 >> 5) | (high_2 >> 6);
    let b2 = 128 | low_1;
    let b3 = 128 | low_2;
    println!("Chars: {c1:b} {c2:b}");
    println!("Bytes: {b1:b} {b2:b} {b3:b}");

    let encyrpted_char = vec![b1, b2, b3];
    String::from_utf8(encyrpted_char)
}

#[cfg(test)]
mod tests {
    use crate::encrypt_char_pair;
    #[test]
    fn single_char_pair() {
        let res = encrypt_char_pair(&b'a', &b'd').expect("must succeed");
        assert_eq!(res, "㡤");
    }
}
