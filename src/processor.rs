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
        sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        // let network_manager = Arc::clone(&self.network_manager);
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
                                    debug!("Attempting to send command to handler task...");
                                    sender
                                        .send(line.trim_start_matches('/').to_string())
                                        .await
                                        .expect("Failed to send command to handler task");
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

                        // encrypt the packet here
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        // User pressed Ctrl+C or Ctrl+D, send a bye bye message and exit
                        debug!("User initiated exit (Ctrl+C or Ctrl+D)");

                        let system_message = ApplicationMessage {
                            content: mic_drop.clone(),
                        };

                        // Give a small delay to allow any pending commands to be processed
                        // tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        // std::process::exit(0);
                        break;
                    }
                    Err(err) => {
                        error!("Error: {err}");
                        break;
                    }
                }
            }
        })
    }

    pub fn spawn_command_handler_task(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<String>,
    ) -> tokio::task::JoinHandle<()> {
        let identity_handle = self.identity.handle.clone();
        tokio::spawn(async move {
            debug!(
                "Command handler task for agent '{}' starting",
                identity_handle
            );

            while let Some(command) = receiver.recv().await {
                debug!("Command handler received command: {:?}", command);
                // match command {
                //     Command::Quit => {
                //         debug!("Quit command received. Exiting command handler task.");
                //         break; // Exit the loop to terminate the task gracefully
                //     }
                //     Command::Join { channel, password } => {
                //         debug!(
                //             "Join command received - Channel: {}, Password: {:?}",
                //             channel, password
                //         );
                //         // TODO: Implement channel joining logic
                //     }
                //     Command::Leave { channel } => {
                //         debug!("Leave command received - Channel: {:?}", channel);
                //         // TODO: Implement channel leaving logic
                //     }
                //     Command::Msg { user, message } => {
                //         debug!(
                //             "Message command received - User: {}, Message: {:?}",
                //             user, message
                //         );
                //         // TODO: Implement private messaging logic
                //     }
                //     Command::Nick { nickname } => {
                //         debug!("Nick command received - New nickname: {}", nickname);
                //         // TODO: Implement nickname change logic
                //     }
                //     Command::Users => {
                //         debug!("Users command received");
                //         // TODO: Implement user listing logic
                //     }
                //     Command::Channels => {
                //         debug!("Channels command received");
                //         // TODO: Implement channel listing logic
                //     }
                // }
            }
            debug!(
                "Command handler task terminated for agent '{}'",
                identity_handle
            );
        })
    }
}
