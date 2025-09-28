/// Possible input commands from the user.
/// 

use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(name = "")]
#[command(no_binary_name = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Join a channel
    Join {
        /// Channel name to join
        channel: String,
        /// Optional password
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Leave current or specified channel
    Leave {
        /// Channel to leave (defaults to current)
        channel: Option<String>,
    },
    /// Send a private message
    Msg {
        /// Username to message
        user: String,
        /// Message content
        #[arg(trailing_var_arg = true)]
        message: Vec<String>,
    },
    /// Change nickname
    Nick {
        /// New nickname
        nickname: String,
    },
    /// List users in current channel
    Users,
    /// List available channels
    Channels,
    /// Show help
    Help,
    /// Quit the application
    #[command(alias = "q")]
    Quit,
}
