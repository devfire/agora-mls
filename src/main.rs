use agora_mls::{app::App, cli::ChatArgs, config::Config};

use clap::Parser;
use tracing::{Level, error, info};
use tracing_subscriber;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: ChatArgs = ChatArgs::parse();

    // Set up logging with the specified log level and filter out noisy logs from rustyline
    let filter_directives = format!("{}{}", args.log_level, ",openmls=info,rustyline=info");

    // Initialize tracing subscriber for logging (needed for validation errors)
    // a bit of hack but rustyline cannot go to debug, it pumps out mad amount of info.
    // sorry, rustyline :)
    tracing_subscriber::fmt()
        .with_max_level(args.log_level.parse::<Level>().unwrap_or(Level::INFO))
        // Include thread IDs only if log level is debug or trace
        .with_thread_ids(args.log_level == "debug" || args.log_level == "trace")
        .with_thread_names(args.log_level == "debug" || args.log_level == "trace")
        .with_file(args.log_level == "debug" || args.log_level == "trace")
        .with_line_number(args.log_level == "debug" || args.log_level == "trace")
        .with_env_filter(filter_directives)
        .init();

    // Validate arguments
    if let Err(e) = args.validate() {
        error!("Error: {}", e);
        std::process::exit(1);
    }

    info!("Starting chat with options: {}", args);

    let config = Config::from_cli(args);
    let mut app = App::new(config);

    app.run().await?;
    Ok(())
}
