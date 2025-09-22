use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenSSHKeyError {
    #[error("Failed to read SSH key file: {ssh_key_file_path}")]
    MissingSshKeyFile { ssh_key_file_path: String },
}
