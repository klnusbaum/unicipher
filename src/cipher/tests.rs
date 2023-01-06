use super::{Cipher, Decrypter, Encrypter, Extended, Standard};
use anyhow::Result;
use std::io::Cursor;

#[test]
fn standard_tests() {
    test_suite(Standard {})
}

#[test]
fn extended_tests() {
    test_suite(Extended {})
}

fn test_suite<C: Cipher<N>, const N: usize>(cipher: C) {
    let test_cases = ["ad", "adgc", "bbb", "x", "another", "hello there"];
    for case in test_cases {
        let encrypted = encrypt_string(case, cipher).expect("encryption failed");
        let decrypted = decrypt_string(&encrypted, cipher).expect("decryption failed");
        assert_eq!(case, decrypted);
    }
}

fn encrypt_string<C, const N: usize>(to_encrypt: &str, cipher: C) -> Result<String>
where
    C: Cipher<N>,
{
    let reader = Cursor::new(to_encrypt);
    let buf_size = encrypt_size::<N>(to_encrypt);
    let mut result = Vec::with_capacity(buf_size);
    Encrypter::new(&mut result, cipher).encrypt(reader)?;
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
    Decrypter::new(&mut result, cipher).decrypt(reader)?;
    Ok(String::from_utf8(result)?)
}

fn decrypt_size<const N: usize>(to_decrypt: &str) -> usize {
    let num_bytes = to_decrypt.bytes().len();
    let num_encrypted_chars = num_bytes / N;
    return num_encrypted_chars * 2;
}
