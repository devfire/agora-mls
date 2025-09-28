#[derive(Debug)]
pub struct Config {
    /// Chat client ID
    pub chat_id: String,

    /// Log level (error, warn, info, debug, trace)
    pub log_level: String,

    /// UDP multicast address for agent communication
    pub multicast_address: std::net::SocketAddr,

    /// Network interface to bind to (optional)
    pub interface: Option<String>,

    /// Private key file path (optional)
    pub key_file: std::path::PathBuf,
}

impl Config {
    /// Creates a new `Config` instance from command-line arguments.
    ///
    /// This constructor takes a [`ChatArgs`] struct containing parsed CLI arguments and
    /// constructs a `Config` instance with the appropriate configuration values. This is
    /// the primary way to initialize the application configuration from user-provided
    /// command-line options.
    pub fn from_cli(args: crate::cli::ChatArgs) -> Self {
        Self {
            chat_id: args.chat_id,
            log_level: args.log_level,
            multicast_address: args.multicast_address,
            interface: args.interface,
            key_file: args.key_file,
        }
    }
}
