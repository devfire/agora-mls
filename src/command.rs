/// Possible input commands from the user.
///
use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(name = "")]
#[command(no_binary_name = true)]
#[command(disable_help_flag = true)] 
struct CommandInput {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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

    /// Quit the application
    #[command(alias = "q")]
    Quit,
}

impl Commands {
    /// Parse a command from a string input
    pub fn parse_command(input: &str) -> Result<Self, clap::Error> {
        let args = shell_words::split(&input[1..])
            .map_err(|e| {
                tracing::error!("Error parsing command: {}", e);
            })
            .unwrap_or_default();
        Ok(CommandInput::try_parse_from(args)?.command)
        // Some(command_input.command)
    }
}
