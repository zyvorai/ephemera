use crate::error::Result;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct VirtioBlockConfig {
    pub path: PathBuf,
    pub read_only: bool,
}

pub fn open_image(path: &std::path::Path) -> Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}
