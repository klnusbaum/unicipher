use crate::cipher::Cipher;
use anyhow::Result;

mod cipher;

fn main() -> Result<()> {
    let cipher = cipher::Simple {};
    let encrypted = cipher.encrypt("adgc".as_bytes())?;
    println!("Encrytped is: '{}'", encrypted);
    let decrypted = cipher.decrypt(encrypted.as_bytes())?;
    println!("Decrypted is: '{}'", decrypted);
    Ok(())
}

// Two ciphers.
// One simple.
// The other ensuring the generated unicode lands in the hieroglyphs area
// https://en.wikipedia.org/wiki/Egyptian_Hieroglyphs_(Unicode_block)
