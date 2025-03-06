use anyhow::Result;
use std::path::{Path, PathBuf};
use std::fs;
use tracing::{info, warn};
use sanitize_filename::sanitize;

pub struct PostProcessor {
    temp_dir: PathBuf,
    final_dir: PathBuf,
}

impl PostProcessor {
    pub fn new(temp_dir: PathBuf, final_dir: PathBuf) -> Self {
        Self {
            temp_dir,
            final_dir,
        }
    }

    pub async fn process_download(&self, job_name: &str, files: Vec<PathBuf>) -> Result<()> {
        let safe_name = sanitize(job_name);
        let job_dir = self.final_dir.join(&safe_name);
        fs::create_dir_all(&job_dir)?;

        for file in files {
            if self.is_archive(&file) {
                info!("Extracting archive: {}", file.display());
                self.extract_archive(&file, &job_dir).await?;
                fs::remove_file(file)?; // Clean up archive after extraction
            } else {
                // Move non-archive files to the job directory
                let target = job_dir.join(file.file_name().unwrap());
                fs::rename(file, target)?;
            }
        }

        self.cleanup_job_dir(&job_dir)?;
        Ok(())
    }

    fn is_archive(&self, path: &Path) -> bool {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        
        matches!(ext.as_str(), "rar" | "zip" | "7z")
    }

    async fn extract_archive(&self, archive_path: &Path, output_dir: &Path) -> Result<()> {
        match archive_path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
        {
            Some(ext) => match ext.as_str() {
                "rar" => self.extract_rar(archive_path, output_dir)?,
                "zip" => self.extract_zip(archive_path, output_dir)?,
                "7z" => self.extract_7z(archive_path, output_dir)?,
                _ => warn!("Unsupported archive type: {}", ext),
            },
            None => warn!("File has no extension: {}", archive_path.display()),
        }

        Ok(())
    }

    fn extract_rar(&self, archive_path: &Path, output_dir: &Path) -> Result<()> {
        let archive_str = archive_path.to_str().unwrap();
        let output_str = output_dir.to_str().unwrap();
        
        match rar::Archive::extract_all(archive_str, output_str, "") {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("Failed to extract RAR archive: {}", e)),
        }
    }

    fn extract_zip(&self, archive_path: &Path, output_dir: &Path) -> Result<()> {
        let file = fs::File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let out_path = output_dir.join(file.name());

            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            if file.is_file() {
                let mut out_file = fs::File::create(&out_path)?;
                std::io::copy(&mut file, &mut out_file)?;
            }
        }
        Ok(())
    }

    fn extract_7z(&self, archive_path: &Path, output_dir: &Path) -> Result<()> {
        sevenz_rust::decompress_file(
            archive_path.to_str().unwrap(),
            output_dir.to_str().unwrap()
        )?;
        Ok(())
    }

    fn cleanup_job_dir(&self, job_dir: &Path) -> Result<()> {
        // Remove any empty directories
        for entry in fs::read_dir(job_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && is_dir_empty(&path)? {
                fs::remove_dir(path)?;
            }
        }
        Ok(())
    }
}

fn is_dir_empty(dir: &Path) -> Result<bool> {
    Ok(fs::read_dir(dir)?.next().is_none())
} 