use anyhow::{Context, Error};

use crate::{get_hjz_directory, TarballListEntry};

pub fn get_storage_dir() -> Result<String, Error> {
  Ok(format!("{}/{}", get_hjz_directory()?, "storage"))
}

pub fn write_tarball(name: String, data: &[u8]) -> Result<(), Error> {
  let storage_dir = get_storage_dir()?;
  let id = sha256::digest(data);
  let tarball_path = format!("{}/{}-data", storage_dir, id);
  let metadata_path = format!("{}/{}-metadata", storage_dir, id);
  std::fs::write(tarball_path, data)?;
  std::fs::write(
    metadata_path,
    serde_json::to_string(&TarballListEntry {
      id,
      name,
      size: data.len() as u64,
    })?,
  )?;
  Ok(())
}

pub fn read_tarball(id: &str) -> Result<Vec<u8>, Error> {
  let storage_dir = get_storage_dir()?;
  let tarball_path = format!("{}/{}-data", storage_dir, id);
  Ok(std::fs::read(tarball_path).with_context(|| format!("Failed to read tarball {}", id))?)
}

pub fn delete_tarball(id: &str) -> Result<(), Error> {
  let storage_dir = get_storage_dir()?;
  let tarball_path = format!("{}/{}-data", storage_dir, id);
  let metadata_path = format!("{}/{}-metadata", storage_dir, id);
  std::fs::remove_file(metadata_path)
    .with_context(|| format!("Failed to delete tarball {}", id))?;
  std::fs::remove_file(tarball_path).with_context(|| {
    format!("BUG: Failed to delete main data, but succeeded at deleteing metadata for {}", id)
  })?;
  Ok(())
}

pub fn list_tarballs() -> Result<Vec<TarballListEntry>, Error> {
  let storage_dir = get_storage_dir()?;
  let mut tarballs = Vec::new();
  for entry in std::fs::read_dir(storage_dir)? {
    let entry = entry?;
    let path = entry.path();
    if path.is_file() {
      let filename = path.file_name().unwrap().to_str().unwrap();
      if filename.ends_with("-metadata") {
        let metadata: TarballListEntry = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        tarballs.push(metadata);
      }
    }
  }
  Ok(tarballs)
}
