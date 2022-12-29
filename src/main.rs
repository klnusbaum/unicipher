mod cipher;

use anyhow::Result;
use cipher::simple;

fn main() -> Result<()> {
    let encrypted = simple::encrypt_string("adgc")?;
    println!("Encrytped is: '{}'", encrypted);
    let decrypted = simple::decrypt_string(&encrypted)?;
    println!("Decrypted is: '{}'", decrypted);
    Ok(())
}

// Two ciphers.
// One simple.
// The other ensuring the generated unicode lands in the hieroglyphs area
// https://en.wikipedia.org/wiki/Egyptian_Hieroglyphs_(Unicode_block)
