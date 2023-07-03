use std::path::{Path, PathBuf};

use anyhow::{Context, Error};

use crate::{get_hjz_directory, ResourceListEntry};

pub fn get_storage_dir() -> Result<PathBuf, Error> {
  Ok(get_hjz_directory()?.join("storage"))
}

pub fn write_resource(name: String, data: &[u8]) -> Result<String, Error> {
  let storage_dir = get_storage_dir()?;
  // IDs are the first 160 bits of the SHA256 hash of the contents.
  let mut id = sha256::digest(data);
  id.truncate(40);
  let resource_path = storage_dir.join(format!("{}-data", id));
  let metadata_path = storage_dir.join(format!("{}-metadata", id));
  std::fs::write(resource_path, data)?;
  std::fs::write(
    metadata_path,
    serde_json::to_string(&ResourceListEntry {
      id: id.clone(),
      name,
      size: data.len() as u64,
    })?,
  )?;
  Ok(id)
}

pub fn read_resource(id: &str) -> Result<Vec<u8>, Error> {
  let storage_dir = get_storage_dir()?;
  let resource_path = storage_dir.join(format!("{}-data", id));
  Ok(std::fs::read(resource_path).with_context(|| format!("Failed to read resource {}", id))?)
}

pub fn copy_resource(id: &str, destination: &Path) -> Result<(), Error> {
  let storage_dir = get_storage_dir()?;
  let resource_path = storage_dir.join(format!("{}-data", id));
  std::fs::copy(resource_path, destination)?;
  Ok(())
}

pub fn delete_resource(id: &str) -> Result<(), Error> {
  let storage_dir = get_storage_dir()?;
  let resource_path = storage_dir.join(format!("{}-data", id));
  let metadata_path = storage_dir.join(format!("{}-metadata", id));
  std::fs::remove_file(metadata_path)
    .with_context(|| format!("Failed to delete resource {}", id))?;
  std::fs::remove_file(resource_path).with_context(|| {
    format!("BUG: Failed to delete main data, but succeeded at deleteing metadata for {}", id)
  })?;
  Ok(())
}

pub fn list_resources() -> Result<Vec<ResourceListEntry>, Error> {
  let storage_dir = get_storage_dir()?;
  let mut resources = Vec::new();
  for entry in std::fs::read_dir(storage_dir)? {
    let entry = entry?;
    let path = entry.path();
    if path.is_file() {
      let filename = path.file_name().unwrap().to_str().unwrap();
      if filename.ends_with("-metadata") {
        let metadata: ResourceListEntry = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        resources.push(metadata);
      }
    }
  }
  Ok(resources)
}
