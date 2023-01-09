use super::{Cipher, Extended, Standard};
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

            #[test]
            fn ascii_pairs() {
                all_ascii_pairs($cipher);
            }
        }
    };
}

cipher_suite!(standard_tests, Standard, Standard);
cipher_suite!(extended_tests, Extended, Extended);

fn all_ascii_pairs<C: Cipher<N>, const N: usize>(cipher: C) {
    for c0 in 0b0010_0000..0b0111_1111 {
        for c1 in 0b0010_0000..0b0111_1111 {
            let byte_pair = (c0, Some(c1));
            let encrypted = cipher.encrypt_char_pair(byte_pair);
            let decrypted = cipher.decrypt_char_pair(encrypted);
            assert_eq!(byte_pair, decrypted);
        }
    }

    for c0 in 0b0010_0000..0b0111_1111 {
        let byte_pair = (c0, None);
        let encrypted = cipher.encrypt_char_pair(byte_pair);
        let decrypted = cipher.decrypt_char_pair(encrypted);
        assert_eq!(byte_pair, decrypted);
    }
}

fn encrypt_string<C, const N: usize>(to_encrypt: &str, cipher: C) -> Result<String>
where
    C: Cipher<N>,
{
    let reader = Cursor::new(to_encrypt);
    let buf_size = encrypt_size::<N>(to_encrypt);
    let mut result = Vec::with_capacity(buf_size);
    cipher.encrypt(reader, &mut result)?;
    Ok(String::from_utf8(result)?)
}

fn encrypt_size<const N: usize>(to_encrypt: &str) -> usize {
    let num_bytes = to_encrypt.bytes().len();
    let num_encrypted_chars_needed = if num_bytes % 2 == 0 {
        num_bytes / 2
    } else {
        (num_bytes / 2) + 1
    };
    return num_encrypted_chars_needed * N;
}

fn decrypt_string<C, const N: usize>(to_decrypt: &str, cipher: C) -> Result<String>
where
    C: Cipher<N>,
{
    let reader = Cursor::new(to_decrypt);
    let buf_size = decrypt_size::<N>(to_decrypt);
    let mut result = Vec::with_capacity(buf_size);
    cipher.decrypt(reader, &mut result)?;
    Ok(String::from_utf8(result)?)
}

fn decrypt_size<const N: usize>(to_decrypt: &str) -> usize {
    let num_bytes = to_decrypt.bytes().len();
    let num_encrypted_chars = num_bytes / N;
    return num_encrypted_chars * 2;
}
