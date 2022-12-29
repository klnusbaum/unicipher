use anyhow::Result;
use std::io::Read;

pub mod simple;

pub trait Encrypt {
    fn encrypt(&mut self, data: impl Read) -> Result<()>;
}

pub trait Decrypt {
    fn decrypt(&mut self, data: impl Read) -> Result<()>;
}
