use anyhow::Result;
use std::io::Read;

pub mod hieroglphys;
pub mod simple;

pub trait Encrypt {
    fn encrypt<R: Read>(&mut self, data: R) -> Result<()>;
}

pub trait Decrypt {
    fn decrypt<R: Read>(&mut self, data: R) -> Result<()>;
}
