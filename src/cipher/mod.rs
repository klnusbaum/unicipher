use anyhow::Result;
use std::io::{Read, Write};

pub mod simple;

pub trait Encrypt {
    fn encrypt(&self, data: impl Read, out: &mut impl Write) -> Result<()>;
}

pub trait Decrypt {
    fn decrypt(&self, data: impl Read, out: &mut impl Write) -> Result<()>;
}
