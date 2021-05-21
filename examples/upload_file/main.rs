use std::{env::args, path::Path};

use qiniu_upload::Uploader;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    for file_path in args().skip(1) {
        println!("Uploading: {}", file_path);

        let uploader = Uploader::from_env().expect("No QINIU ENV is setup");
        let file_name = Path::new(&file_path)
            .file_name()
            .expect("No file name is found");
        uploader
            .upload_path(&file_path)?
            .object_name(&file_path)
            .file_name(file_name.to_string_lossy())
            .upload_progress_callback(Box::new(|progress| {
                println!(
                    "Upload progress: upload id: {}, part number: {}, uploaded: {}",
                    progress.upload_id(),
                    progress.part_number(),
                    progress.uploaded()
                );
                Ok(())
            }))
            .start()?;
        println!("Uploaded: {}", file_path);
    }

    Ok(())
}
