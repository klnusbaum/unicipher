mod decrypt;
mod encrypt;
mod extended;
mod standard;
#[cfg(test)]
mod tests;

pub use decrypt::Decrypter;
pub use encrypt::Encrypter;
pub use extended::Extended;
pub use standard::Standard;

pub trait Cipher<const N: usize> {
    fn encrypt_char_pair(&self, c0: u8, c1: u8) -> [u8; N];
    fn encrypt_single_char(&self, c0: u8) -> [u8; N];
    fn decrypt_single_char(&self, encrypted: [u8; N]) -> [u8; 1];
    fn decrypt_char_pair(&self, encrypted: [u8; N]) -> [u8; 2];
    fn has_single_char(&self, encrypted: [u8; N]) -> bool;
}
