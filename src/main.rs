mod cipher;

use anyhow::Result;
use cipher::simple;

fn main() -> Result<()> {
    let encrypted = simple::encrypt_to_string("adgc".as_bytes())?;
    println!("Encrytped is: '{}'", encrypted);
    let decrypted = simple::decrypt_to_string(encrypted.as_bytes())?;
    println!("Decrypted is: '{}'", decrypted);
    Ok(())
}

// Two ciphers.
// One simple.
// The other ensuring the generated unicode lands in the hieroglyphs area
// https://en.wikipedia.org/wiki/Egyptian_Hieroglyphs_(Unicode_block)
