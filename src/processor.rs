use std::sync::Arc;

use rustyline::{DefaultEditor, error::ReadlineError};
use tracing::{debug, error};

use crate::{agora_chat::ApplicationMessage, command::Command, identity::MyIdentity, network};

pub struct Processor {
    pub identity: MyIdentity,
    pub network_manager: Arc<network::NetworkManager>,
}

impl Processor {
    pub fn new(identity: MyIdentity, network_manager: Arc<network::NetworkManager>) -> Self {
        Self {
            identity,
            network_manager,
        }
    }

    /// Spawn a task to handle user input from stdin.
    pub fn spawn_stdin_input_task(
        &self,
        sender: tokio::sync::mpsc::Sender<Command>,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);
        let handle = self.identity.handle.clone();
        tokio::spawn(async move {
            debug!("Starting stdin input task for agent '{}'", handle);
            let mut rustyline_editor = match DefaultEditor::new() {
                Ok(editor) => editor,
                Err(e) => {
                    error!("Unable to initialized the rustyline editor {e}");
                    return;
                }
            };
            let mic_drop = "User has left the chat.".to_string();

            loop {
                let readline = rustyline_editor.readline(&format!("{} > ", handle));

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
                                    if let Err(e) = sender.send(c).await {
                                        error!("Failed to send command: {e}");
                                    }
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

    pub async fn spawn_command_handler_task(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<Command>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(command) = receiver.recv().await {
                match command {
                    Command::Quit => {
                        debug!("Quit command received. Exiting command handler task.");
                        break;
                    }
                    Command::Join { channel, password } => todo!(),
                    Command::Leave { channel } => todo!(),
                    Command::Msg { user, message } => todo!(),
                    Command::Nick { nickname } => todo!(),
                    Command::Users => todo!(),
                    Command::Channels => todo!(),
                }
            }
        })
    }
}
