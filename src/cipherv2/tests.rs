use super::{CipherV2, Simple};
use anyhow::Result;
use std::io::Cursor;

macro_rules! simple_test {
    ($name:ident,$cipher:expr,$test_case:literal) => {
        #[test]
        fn $name() {
            let encrypted = encrypt_string($test_case, $cipher).expect("encryption failed");
            let decrypted = decrypt_string(&encrypted, $cipher).expect("decryption failed");
            assert_eq!($test_case, decrypted);
        }
    };
}

macro_rules! cipher_suite {
    ($suite_name:ident,$cipher:expr,$cipher_type:ty) => {
        #[cfg(test)]
        mod $suite_name {
            use super::{all_ascii_pairs, decrypt_string, encrypt_string, $cipher_type};

            simple_test!(single_pair, $cipher, "ad");
            simple_test!(two_pair, $cipher, "adgc");
            simple_test!(odd_length_string, $cipher, "bbb");
            simple_test!(single_character, $cipher, "x");
            simple_test!(another, $cipher, "another");
            simple_test!(with_space, $cipher, "hello there");
            simple_test!(
                long_string,
                $cipher,
                "a longer string than most of the others"
            );
            simple_test!(all_caps, $cipher, "CAPITIALIZED STRING");
            simple_test!(mixed_caps, $cipher, "MiXeD cApS");
            simple_test!(special_chars, $cipher, "!@#$%^&*()-_=+|~`,./<>?;':\"[]{}\\");
            simple_test!(numbers, $cipher, "12345567890");
            simple_test!(numbers_and_letters, $cipher, "120 mokneys on 40 barrels");

            #[test]
            fn ascii_pairs() {
                all_ascii_pairs($cipher);
            }
        }
    };
}

cipher_suite!(simple_tests, Simple, Simple);

fn all_ascii_pairs<C: CipherV2>(cipher: C) {
    for c0 in 0b0010_0000..0b0111_1111 {
        for c1 in 0b0010_0000..0b0111_1111 {
            let byte_pair = (c0, c1);
            let encrypted = cipher.encrypt_char_pair(byte_pair);
            let decrypted = cipher.decrypt_char_pair(encrypted);
            assert_eq!(byte_pair, decrypted);
        }
    }

    for c0 in 0b0010_0000..0b0111_1111 {
        let byte_pair = (c0, 0b0000_0000);
        let encrypted = cipher.encrypt_char_pair(byte_pair);
        let decrypted = cipher.decrypt_char_pair(encrypted);
        assert_eq!(byte_pair, decrypted);
    }
}

fn encrypt_string<C>(to_encrypt: &str, cipher: C) -> Result<String>
where
    C: CipherV2,
{
    let reader = Cursor::new(to_encrypt);
    let mut result = Vec::new();
    cipher.encrypt(reader, &mut result)?;
    Ok(String::from_utf8(result)?)
}

fn decrypt_string<C>(to_decrypt: &str, cipher: C) -> Result<String>
where
    C: CipherV2,
{
    let reader = Cursor::new(to_decrypt);
    let mut result = Vec::new();
    cipher.decrypt(reader, &mut result)?;
    Ok(String::from_utf8(result)?)
}
