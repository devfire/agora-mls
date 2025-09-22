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
    ///
    /// # Arguments
    ///
    /// * `args` - A [`ChatArgs`] instance containing the parsed command-line arguments
    ///   from the user. This includes the chat client ID, log level, multicast address,
    ///   network interface, and optional key file path.
    ///
    /// # Returns
    ///
    /// Returns a new `Config` instance with all fields populated from the provided
    /// CLI arguments. The returned configuration is ready to be used for initializing
    /// the chat application.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use clap::Parser;
    /// use crate::cli::ChatArgs;
    /// use crate::config::Config;
    ///
    /// // Parse command-line arguments
    /// let args = ChatArgs::parse();
    ///
    /// // Validate the arguments
    /// if let Err(e) = args.validate() {
    ///     eprintln!("Invalid arguments: {}", e);
    ///     std::process::exit(1);
    /// }
    ///
    /// // Create configuration from CLI args
    /// let config = Config::from_cli(args);
    /// ```
    ///
    /// # See Also
    ///
    /// * [`ChatArgs`] - The command-line argument structure
    /// * [`Config`] - The main configuration struct this method constructs
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
