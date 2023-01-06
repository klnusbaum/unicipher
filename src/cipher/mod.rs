mod decrypt;
mod encrypt;
mod extended;
mod standard;
#[cfg(test)]
mod tests;

pub use decrypt::{Chars, Decrypter};
pub use encrypt::Encrypter;
pub use extended::Extended;
pub use standard::Standard;

pub trait Cipher<const N: usize>: Copy {
    fn encrypt_char_pair(&self, c0: u8, c1: Option<u8>) -> [u8; N];
    fn decrypt_char_pair(&self, encrypted: [u8; N]) -> (u8, Option<u8>);
}
