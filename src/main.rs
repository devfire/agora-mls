use agora_mls::cli::ChatArgs;

use clap::Parser;
use tracing::{error, info};

fn main() {
    let args = ChatArgs::parse();

    // Validate arguments
    if let Err(e) = args.validate() {
        error!("Error: {}", e);
        std::process::exit(1);
    }

    info!("Starting chat with options: {:?}", args);
}
