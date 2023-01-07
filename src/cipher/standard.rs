use super::Cipher;

const SIG_BIT_MASK: u8 = 0b0100_0000;
const LOWER_BITS_MASK: u8 = 0b0011_1111;
const SINGLE_CHAR_MASK: u8 = 0b0000_0100;

pub struct Standard {}

impl Cipher<3> for Standard {
    fn encrypt_char_pair(&self, c0: u8, c1: Option<u8>) -> [u8; 3] {
        let mut encrypted_char = [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 0b1110_0000 | (sig_0 >> 5);
        encrypted_char[1] = 0b1000_0000 | low_0;
        if let Some(c1) = c1 {
            let sig_1 = c1 & SIG_BIT_MASK;
            let low_1 = c1 & LOWER_BITS_MASK;
            encrypted_char[0] = encrypted_char[0] | (sig_1 >> 6);
            encrypted_char[2] = 0b1000_0000 | low_1;
        } else {
            encrypted_char[0] = encrypted_char[0] | SINGLE_CHAR_MASK;
            encrypted_char[2] = 0b1000_0000;
        }
        return encrypted_char;
    }

    fn decrypt_char_pair(&self, encrypted: [u8; 3]) -> (u8, Option<u8>) {
        let c0_sig_bit = (encrypted[0] & 2) << 5;
        let c0_lower = encrypted[1] & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;

        if encrypted[0] & SINGLE_CHAR_MASK != 0 {
            return (c0, None);
        }

        let c1_sig_bit = (encrypted[0] & 1) << 6;
        let c1_lower = encrypted[2] & LOWER_BITS_MASK;
        let c1 = c1_sig_bit | c1_lower;
        return (c0, Some(c1));
    }
}
