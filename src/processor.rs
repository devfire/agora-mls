use std::sync::Arc;

use rustyline::{DefaultEditor, error::ReadlineError};
use tracing::{debug, error};

use crate::{
    agora_chat::ApplicationMessage, command::Command, handle_command::handle_command, network,
};

pub struct Processor {
    pub network_manager: Arc<network::NetworkManager>,
}

impl Processor {
    pub fn new(network_manager: Arc<network::NetworkManager>) -> Self {
        Self { network_manager }
    }

    /// Spawn a task to handle user input from stdin.
    pub fn spawn_stdin_input_task(&self, chat_id: &str) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);

        let chat_id = chat_id.to_string();

        tokio::spawn(async move {
            debug!("Starting stdin input task for agent '{}'", chat_id);
            let mut rustyline_editor = match DefaultEditor::new() {
                Ok(editor) => editor,
                Err(e) => {
                    error!("Unable to initialized the rustyline editor {e}");
                    return;
                }
            };
            let mic_drop = "User has left the chat.".to_string();

            loop {
                let readline = rustyline_editor.readline(&format!("{} > ", chat_id));

                match readline {
                    Ok(line) => {
                        if line.is_empty() {
                            continue;
                        }
                        if let Err(e) = rustyline_editor.add_history_entry(line.as_str()) {
                            error!("Could not even add to history {e}")
                        }

                        // check to see if input starts with `/` which indicates a command
                        if line.starts_with('/') {
                            // handle commands here
                            match Command::parse_command(&line) {
                                Ok(c) => {
                                    debug!("Command entered: {:?}", c);
                                    // Handle the command supplied
                                    handle_command(c);
                                    continue;
                                }
                                Err(e) => {
                                    // Check if this is a help request
                                    if e.kind() == clap::error::ErrorKind::DisplayHelp {
                                        // Print help text
                                        Command::show_custom_help();
                                    } else {
                                        error!("Command processing failed with {e}");
                                    }
                                    continue;
                                }
                            }
                        }
                        debug!("Stdin input read line: {}", line);

                        // encrypt the packet here
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        // User pressed Ctrl+C or Ctrl+D, send a bye bye message and exit
                        debug!("User initiated exit (Ctrl+C or Ctrl+D)");

                        let system_message = ApplicationMessage {
                            content: mic_drop.clone(),
                        };
                        std::process::exit(0);
                    }
                    Err(err) => {
                        error!("Error: {err}");
                        break;
                    }
                }
            }
        })
    }
}
