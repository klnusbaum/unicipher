use anyhow::Result;
use std::io::{Read, Write};

pub mod simple;

pub trait Encrypt {
    fn encrypt<R: Read, W: Write>(&self, data: R, out: &mut W) -> Result<()>;
}

pub trait Decrypt {
    fn decrypt<R: Read, W: Write>(&self, data: R, out: &mut W) -> Result<()>;
}
