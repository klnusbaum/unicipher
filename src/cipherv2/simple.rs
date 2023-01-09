use super::{BytePair, CipherV2};

const C0_MASK: u32 = 0b0011_1111_1000_0000;
const C1_MASK: u32 = 0b0111_1111;

pub struct Simple;

impl CipherV2 for Simple {
    fn encrypt_char_pair(&self, pair: BytePair) -> char {
        let c0 = pair.0 as u16;
        let c1 = pair.1 as u16;
        let to_encrypt = (c0 << 7) | c1;
        return char::from_u32(to_encrypt as u32).unwrap(); // we should always produce valid utf8,
                                                           // if not, that's a bug and we should
                                                           // panic.
    }

    fn decrypt_char_pair(&self, encrypted: char) -> BytePair {
        let bytes = encrypted as u32;
        let c0 = (bytes & C0_MASK) >> 7;
        let c1 = bytes & C1_MASK;
        (c0.to_be_bytes()[3], c1.to_be_bytes()[3])
    }
}
