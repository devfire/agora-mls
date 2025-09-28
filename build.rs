use std::io::Result;
use std::path::Path;

fn main() -> Result<()> {
    // Generate the protobuf code to OUT_DIR (standard location)
    prost_build::compile_protos(&["proto/chat.proto"], &["proto/"])?;

    // For development, create a copy in src/ directory so rust-analyzer can find it
    if let Ok(out_dir) = std::env::var("OUT_DIR") {
        let out_path = Path::new(&out_dir);
        let generated_file = out_path.join("agora_chat.rs");

        if generated_file.exists() {
            let src_file = Path::new("src").join("agora_chat.rs");
            std::fs::copy(&generated_file, &src_file)?;
        }
    }

    Ok(())
}