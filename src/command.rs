/// Possible input commands from the user.
///
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
#[command(name = "")]
#[command(no_binary_name = true)]
pub struct CommandWrapper {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Join a channel
    Invite {
        /// Channel name to join
        #[arg(help = "Name of the channel to join")]
        channel: String,
        /// Optional password
        #[arg(help = "Channel password (if required)")]
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
    /// Create a new group
    Create {
        /// New group name
        name: String,
    },
    /// List users in current channel
    Users,
    /// List available channels
    Channels,

    /// Quit the application
    #[command(alias = "q")]
    Quit,
}

impl Command {
    /// Parse a command from a string input
    pub fn parse_command(input: &str) -> Result<Self, clap::Error> {
        let args = shell_words::split(&input[1..]).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("Shell parsing error: {}", e),
            )
        })?;

        // Handle the automatic help command
        if args.is_empty()
            || args
                .iter()
                .any(|arg| arg == "help" || arg == "--help" || arg == "-h")
        {
            // Return an error that indicates help was requested
            // This will be caught by the caller to display help
            return Err(clap::Error::raw(
                clap::error::ErrorKind::DisplayHelp,
                "Help requested",
            ));
        }

        CommandWrapper::try_parse_from(args).map(|wrapper| wrapper.command)
    }

    pub fn show_custom_help() {
        println!("╭─ Chat Commands ─────────────────────────────────────────╮");
        println!("│                                                         │");
        println!("│  /join <channel> [password]     Join a channel          │");
        println!("│  /leave [channel]               Leave channel           │");
        println!("│  /msg <user> <message>          Send private message    │");
        println!("│  /nick <nickname>               Change your nickname    │");
        println!("│  /users                         List users in channel   │");
        println!("│  /channels                      List available channels │");
        println!("│  /help                          Show this help          │");
        println!("│  /quit, /q                      Exit the chat           │");
        println!("│                                                         │");
        println!("│  Examples:                                              │");
        println!("│    /join #general                                       │");
        println!("│    /join #private secret123                             │");
        println!("│    /msg alice Hey there!                                │");
        println!("│    /nick CoolUser                                       │");
        println!("│                                                         │");
        println!("╰─────────────────────────────────────────────────────────╯");
    }
}
