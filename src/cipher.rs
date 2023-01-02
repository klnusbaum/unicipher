const SIG_BIT_MASK: u8 = 127;
const LOWER_BITS_MASK: u8 = 63;
const SINGLE_CHAR_MASK: u8 = 4;

pub trait Algorithm<const N: usize> {
    fn encrypt_char_pair(&self, c0: u8, c1: u8) -> [u8; N];
    fn encrypt_single_char(&self, c0: u8) -> [u8; N];
    fn decrypt_single_char(&self, encrypted: [u8; N]) -> [u8; 1];
    fn decrypt_char_pair(&self, encrypted: [u8; N]) -> [u8; 2];
    fn has_single_char(&self, encrypted: [u8; N]) -> bool;
}

pub struct Standard {}

impl Algorithm<3> for Standard {
    fn encrypt_char_pair(&self, c0: u8, c1: u8) -> [u8; 3] {
        let mut encrypted_char = [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128 | low_1;
        return encrypted_char;
    }

    fn encrypt_single_char(&self, c0: u8) -> [u8; 3] {
        let mut encrypted_char = [0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 224 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[1] = 128 | low_0;
        encrypted_char[2] = 128;
        return encrypted_char;
    }

    fn decrypt_char_pair(&self, encrypted: [u8; 3]) -> [u8; 2] {
        let c0_sig_bit = (encrypted[0] & 2) << 5;
        let c1_sig_bit = (encrypted[0] & 1) << 6;
        let c0_lower = encrypted[1] & LOWER_BITS_MASK;
        let c1_lower = encrypted[2] & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        return [c0, c1];
    }

    fn decrypt_single_char(&self, encrypted: [u8; 3]) -> [u8; 1] {
        let sig_bit = (encrypted[0] & 1) << 6;
        let lower = encrypted[1] & LOWER_BITS_MASK;
        return [sig_bit | lower];
    }

    fn has_single_char(&self, encrypted: [u8; 3]) -> bool {
        encrypted[0] & SINGLE_CHAR_MASK != 0
    }
}

pub struct Extended {}

impl Algorithm<4> for Extended {
    fn encrypt_char_pair(&self, c0: u8, c1: u8) -> [u8; 4] {
        let mut encrypted_char = [0, 0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let sig_1 = c1 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        let low_1 = c1 & LOWER_BITS_MASK;
        encrypted_char[0] = 240;
        encrypted_char[1] = 144 | (sig_0 >> 5) | (sig_1 >> 6);
        encrypted_char[2] = 128 | low_0;
        encrypted_char[3] = 128 | low_1;
        return encrypted_char;
    }

    fn encrypt_single_char(&self, c0: u8) -> [u8; 4] {
        let mut encrypted_char = [0, 0, 0, 0];
        let sig_0 = c0 & SIG_BIT_MASK;
        let low_0 = c0 & LOWER_BITS_MASK;
        encrypted_char[0] = 240;
        encrypted_char[1] = 144 | SINGLE_CHAR_MASK | (sig_0 >> 6);
        encrypted_char[2] = 128 | low_0;
        encrypted_char[3] = 128;
        return encrypted_char;
    }

    fn decrypt_char_pair(&self, encrypted: [u8; 4]) -> [u8; 2] {
        let c0_sig_bit = (encrypted[1] & 2) << 5;
        let c1_sig_bit = (encrypted[1] & 1) << 6;
        let c0_lower = encrypted[2] & LOWER_BITS_MASK;
        let c1_lower = encrypted[3] & LOWER_BITS_MASK;
        let c0 = c0_sig_bit | c0_lower;
        let c1 = c1_sig_bit | c1_lower;
        return [c0, c1];
    }

    fn decrypt_single_char(&self, encrypted: [u8; 4]) -> [u8; 1] {
        let sig_bit = (encrypted[1] & 1) << 6;
        let lower = encrypted[2] & LOWER_BITS_MASK;
        return [sig_bit | lower];
    }

    fn has_single_char(&self, encrypted: [u8; 4]) -> bool {
        encrypted[1] & SINGLE_CHAR_MASK != 0
    }
}

#[cfg(test)]
mod standard_tests {
    use super::Standard;
    use crate::decrypt::decrypt_string;
    use crate::encrypt::encrypt_string;

    #[test]
    fn single_char_pair() {
        let res = encrypt_string("ad", Standard {}).expect("must succeed");
        assert_eq!(res, "㡤");
        let decrypted = decrypt_string(&res, Standard {}).expect("must succeed");
        assert_eq!(decrypted, "ad");
    }

    #[test]
    fn even_length_string() {
        let res = encrypt_string("adgc", Standard {}).expect("must succeed");
        assert_eq!(&res, "㡤㧣");
        let decrypted = decrypt_string(&res, Standard {}).expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }

    #[test]
    fn odd_length_string() {
        let res = encrypt_string("bbb", Standard {}).expect("must succeed");
        assert_eq!(&res, "㢢墀");
        let decrypted = decrypt_string(&res, Standard {}).expect("must succeed");
        assert_eq!(decrypted, "bbb");
    }

    #[test]
    fn single_char_string() {
        let res = encrypt_string("x", Standard {}).expect("must succeed");
        assert_eq!(&res, "帀");
        let decrypted = decrypt_string(&res, Standard {}).expect("must succeed");
        assert_eq!(decrypted, "x");
    }
}

#[cfg(test)]
mod extended_tests {
    use super::Extended;
    use crate::decrypt::decrypt_string;
    use crate::encrypt::encrypt_string;

    #[test]
    fn single_char_pair() {
        // a = 97
        // d = 100
        // a = 01100001
        // d = 01100100
        // a sig = 1
        // d sig = 1
        // a lower = 100001
        // d lower = 100100
        // b0 = 1111000
        // b1 = 10010011
        // b2 = 10100001
        // b3 = 10100100
        // code point = 0 0001 0011 1000 0110 0100
        // code point =   1    3    8    6    4
        let res = encrypt_string("ad", Extended {}).expect("must succeed");
        assert_eq!(res, "\u{13864}");
        let decrypted = decrypt_string(&res, Extended {}).expect("must succeed");
        assert_eq!(decrypted, "ad");
    }

    #[test]
    fn even_length_string() {
        let res = encrypt_string("adgc", Extended {}).expect("must succeed");
        assert_eq!(res, "\u{13864}\u{139e3}");
        let decrypted = decrypt_string(&res, Extended {}).expect("must succeed");
        assert_eq!(decrypted, "adgc");
    }

    #[test]
    fn odd_length_string() {
        // b = 98
        // b = 98
        // b = 01100010
        // b = 01100010
        // b sig = 1
        // b sig = 1
        // b lower = 100010
        // b lower = 100010
        // b0 = 1111000
        // b1 = 10010011
        // b2 = 10100010
        // b3 = 10100010
        // code point = 0 0001 0011 1000 1010 0010
        // code point =   1    3    8    a    2
        //
        // b = 98
        // b = 01100010
        // b sig = 1
        // b lower = 100010
        // b0 = 11110000
        // b1 = 10010101
        // b2 = 10100010
        // b3 = 10000000
        // code point = 0 0001 0101 1000 1000 0000
        // code point =   1    5    8    8    0
        let res = encrypt_string("bbb", Extended {}).expect("must succeed");
        assert_eq!(res, "\u{138a2}\u{15880}");
        let decrypted = decrypt_string(&res, Extended {}).expect("must succeed");
        assert_eq!(decrypted, "bbb");
    }

    #[test]
    fn single_char_string() {
        let res = encrypt_string("x", Extended {}).expect("must succeed");
        assert_eq!(res, "\u{15e00}");
        let decrypted = decrypt_string(&res, Extended {}).expect("must succeed");
        assert_eq!(decrypted, "x");
    }
}
