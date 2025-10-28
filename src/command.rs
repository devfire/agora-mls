/// Possible input commands from the user.
///
use clap::{Parser, Subcommand};

use crate::crypto_identity_actor::{CryptoIdentityMessage, UserIdentity};

// rustyline completer
use rustyline::completion::{Completer, Pair};
use rustyline::Context;
use rustyline::hint::Hinter;
use rustyline::highlight::Highlighter;
use rustyline::validate::Validator;
use rustyline::Helper;

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
        /// Username name to invite
        #[arg(help = "Name of the user to invite")]
        nick: String,
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
    CreateGroup {
        /// New group name
        name: String,
    },
    /// List known users
    Users,

    /// List available groups
    Groups,

    /// Display information about current active group or set active group
    Group {
        /// Set group to active
        name: String,
    },

    /// Generate the safety number for the current identity
    Safety,

    /// Send out the mls key package
    Announce,

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

// In src/command.rs
impl Command {
    pub fn to_crypto_message(&self) -> Option<CryptoIdentityMessage> {
        match self {
            Command::CreateGroup { name } => Some(CryptoIdentityMessage::CreateGroup {
                group_name: name.clone(),
            }),
            Command::Invite { nick, .. } => nick
                .parse::<UserIdentity>()
                .ok()
                .map(CryptoIdentityMessage::InviteUser),
            Command::Groups => Some(CryptoIdentityMessage::ListGroups),
            Command::Group { name } => Some(CryptoIdentityMessage::SetCurrentGroup(name.to_owned())),
            Command::Users => Some(CryptoIdentityMessage::ListUsers),
            Command::Announce => Some(CryptoIdentityMessage::CreateAnnouncement),
            // Non-crypto commands return None
            _ => None,
        }
    }
}


pub struct CommandCompleter;

impl CommandCompleter {
    /// Get all available command names
    pub fn get_commands() -> Vec<&'static str> {
        vec![
            "invite",
            "leave",
            "msg",
            "create-group",
            "users",
            "groups",
            "group",
            "safety",
            "announce",
            "quit",
            "q",
        ]
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        _pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        if !line.starts_with('/') {
            return Ok((0, vec![]));
        }

        let input = &line[1..];
        let mut completions = Vec::new();

        for cmd in Self::get_commands() {
            if cmd.starts_with(input) {
                completions.push(Pair {
                    display: format!("/{}", cmd),
                    replacement: format!("/{}", cmd),
                });
            }
        }

        Ok((0, completions))
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        // Only hint if we're at the end of the line
        if pos < line.len() {
            return None;
        }

        // Only hint for commands (lines starting with /)
        if !line.starts_with('/') {
            return None;
        }

        let input = &line[1..];
        
        // Find the first command that starts with the input
        for cmd in Self::get_commands() {
            if cmd.starts_with(input) && cmd.len() > input.len() {
                // Return the remaining part of the command
                return Some(cmd[input.len()..].to_string());
            }
        }

        None
    }
}

impl Highlighter for CommandCompleter {}

impl Validator for CommandCompleter {}

impl Helper for CommandCompleter {}