use super::{BytePair, Cipher};

const SIG_BIT_MASK: u8 = 0b0100_0000;
const LOWER_BITS_MASK: u8 = 0b0011_1111;
const SINGLE_CHAR_MASK: u8 = 0b0000_0100;
const CHAR_WIDTH_MASK: u8 = 0b1111_0000;
const CONINUATION_MASK: u8 = 0b1000_0000;
// Needed to ensure that our generated code point is in the acceptable range for a
// 4-byte unicode character.
const OVERLONG_AVOIDANCE_MASK: u8 = 0b0001_0000;

pub struct Extended;

impl Cipher<4> for Extended {
    fn encrypt_char_pair(&self, pair: BytePair) -> [u8; 4] {
        let mut encrypted_char = [0, 0, 0, 0];
        let c0 = pair.0;
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = CHAR_WIDTH_MASK;
        encrypted_char[1] = CONINUATION_MASK | OVERLONG_AVOIDANCE_MASK | (sig_0 >> 5);
        encrypted_char[2] = CONINUATION_MASK | low_0;

        if let Some(c1) = pair.1 {
            let sig_1 = c1 & SIG_BIT_MASK;
            let low_1 = c1 & LOWER_BITS_MASK;
            encrypted_char[1] = encrypted_char[1] | (sig_1 >> 6);
            encrypted_char[3] = CONINUATION_MASK | low_1;
        } else {
            encrypted_char[1] = encrypted_char[1] | SINGLE_CHAR_MASK;
            encrypted_char[3] = CONINUATION_MASK;
        }
        return encrypted_char;
    }

    fn decrypt_char_pair(&self, encrypted: [u8; 4]) -> BytePair {
        let c0_sig_bit = (encrypted[1] & 2) << 5;
        let c0_lower = encrypted[2] & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;

        if encrypted[1] & SINGLE_CHAR_MASK != 0 {
            return (c0, None);
        }

        let c1_sig_bit = (encrypted[1] & 1) << 6;
        let c1_lower = encrypted[3] & LOWER_BITS_MASK;
        let c1 = c1_sig_bit | c1_lower;
        return (c0, Some(c1));
    }
}
