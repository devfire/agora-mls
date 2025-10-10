use kameo::prelude::ActorRef;
use rustyline::{DefaultEditor, error::ReadlineError};
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    command::Command,
    network,
    state_actor::{StateActor, StateActorReply},
};

pub struct Processor {
    // pub identity: MyIdentity,
    pub network_manager: Arc<network::NetworkManager>,
    // pub state_actor: ActorRef<StateActor>,
}

impl Processor {
    pub fn new(
        // state_actor: ActorRef<StateActor>,
        // identity: MyIdentity,
        network_manager: Arc<network::NetworkManager>,
    ) -> Self {
        Self {
            // identity,
            network_manager,
            // state_actor,
        }
    }

    /// Spawn a task to handle user input from stdin.
    pub fn spawn_stdin_input_task(
        &self,
        state_actor: ActorRef<StateActor>,
        sender: tokio::sync::mpsc::Sender<Command>,
    ) -> tokio::task::JoinHandle<()> {
        // get the chat handle from the state actor

        // let handle = self.identity.handle.clone();

        // Use spawn_blocking to run the synchronous rustyline code.
        /*
        The rustyline crate we are using for command-line input is a synchronous library.
        When we call rustyline_editor.readline(), it blocks the thread until the user enters a line and presses Enter.

        Since we are calling this inside a regular tokio::spawn task, we are blocking one of the tokio worker threads.
        This prevents any other async tasks that are scheduled on that same thread from running.
        In our case, the command_handler_task is likely on the same thread and never gets a chance to run and receive the message from the channel.

        The command only gets processed when a user presses Ctrl+D because that terminates the blocking readline call,
        which in turn allows the stdin_input_task to finish and the tokio runtime to shut down.
        During shutdown, the pending message in the channel is finally processed.

        The Solution: spawn_blocking! :)
        The correct way to handle blocking code within a tokio runtime is to use tokio::task::spawn_blocking.
        This moves the blocking operation to a dedicated thread pool for blocking tasks, leaving the main tokio worker threads free to continue running other async tasks.
        */
        tokio::task::spawn_blocking(move || {
            // debug!("Starting stdin input task for agent '{}'", handle);
            let mut rustyline_editor = match DefaultEditor::new() {
                Ok(editor) => editor,
                Err(e) => {
                    error!("Unable to initialize the rustyline editor {e}");
                    return;
                }
            };

            loop {
                let readline = rustyline_editor.readline(&format!(" > "));

                match readline {
                    Ok(line) => {
                        if line.is_empty() {
                            continue;
                        }
                        if let Err(e) = rustyline_editor.add_history_entry(line.as_str()) {
                            error!("Could not even add to history {e}")
                        }

                        if line.starts_with('/') {
                            match Command::parse_command(&line) {
                                Ok(c) => {
                                    debug!("Command entered: {:?}", c);
                                    debug!("Attempting to send command to handler task...");
                                    // Use blocking_send since we're in a blocking context
                                    if sender.blocking_send(c).is_err() {
                                        error!(
                                            "Failed to send command: receiver has been dropped."
                                        );
                                        break;
                                    }
                                }
                                Err(e) => {
                                    if e.kind() == clap::error::ErrorKind::DisplayHelp {
                                        Command::show_custom_help();
                                    } else {
                                        error!("Command processing failed with {e}");
                                    }
                                }
                            }
                        }
                        // Not a command; send the message to the network manager for broadcasting
                        // else {
                        //     debug!("Sending message to network manager for broadcast: {}", line);
                        //     // Steps are:
                        //     // 1. Get the current active group from the state actor
                        //     // 2. Construct a PlaintextPayload message
                        //     // 3. Encrypt it using the MLS group
                        //     // 4. Send the encrypted message via the network manager
                        //     // 5. The network manager handles the actual UDP multicast sending
                        //     // let result = rt.block_on(async {
                        //     //     // 1. Get the current active group from the state actor
                        //     //     let active_group = match state_actor
                        //     //         .ask(Command::Msg {
                        //     //             user: String::new(),
                        //     //             message: String::new(),
                        //     //         })
                        //     //         .await
                        //     //     {
                        //     //         Ok(StateActorReply::Status(Ok(()))) => {
                        //     //             // Placeholder: Replace with actual method to get active group
                        //     //             // self.state_actor.get_active_group().await
                        //     //             todo!("Implement getting the active group from state actor")
                        //     //         }
                        //     //         Ok(StateActorReply::Status(Err(e))) => {
                        //     //             error!("Failed to get active group: {:?}", e);
                        //     //             return Err(e);
                        //     //         }
                        //     //         Err(e) => {
                        //     //             error!("Failed to communicate with state actor: {}", e);
                        //     //             return Err(e);
                        //     //         }
                        //     //         _ => {
                        //     //             error!("Unexpected reply when getting active group");
                        //     //             return Err(StateActorError::ChannelNotFound);
                        //     //         }
                        //     //     };

                        //     //     // 2. Construct a PlaintextPayload message
                        //     //     let payload = crate::agora_chat::PlaintextPayload {
                        //     //         display_name: identity_handle.clone(),
                        //     //         content: line.clone(),
                        //     //         timestamp: chrono::Utc::now().timestamp_nanos() as u64,
                        //     //     };

                        //     //     // 3. Encrypt it using the MLS group
                        //     //     let encrypted_message = match active_group.encrypt_message(&payload) {
                        //     //         Ok(msg) => msg,
                        //     //         Err(e) => {
                        //     //             error!("Failed to encrypt message: {}", e);
                        //     //             return Err(StateActorError::MessageEncryptionFailed);
                        //     //         }
                        //     //     };

                        //     //     // 4. Send the encrypted message via the network manager
                        //     //     match network_manager.send_message(encrypted_message).await {
                        //     //         Ok(_) => {
                        //     //             debug!("Message broadcast successfully.");
                        //     //             Ok(())
                        //     //         }
                        //     //         Err(e) => {
                        //     //             error!("Failed to send message via network manager: {}", e);
                        //     //             Err(StateActorError::NetworkError)
                        //     //         }
                        //         }
                        //     });
                        // }
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        debug!("User initiated exit (Ctrl+C or Ctrl+D)");
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
        state_actor: ActorRef<StateActor>,
        mut receiver: tokio::sync::mpsc::Receiver<Command>,
    ) -> tokio::task::JoinHandle<()> {
        // let identity_handle = self.identity.handle.clone();
        tokio::spawn(async move {
            // let identity_handle = state_actor
            //     .ask(Command::Nick { nickname: None })
            //     .await
            //     .expect("Unable to get chat handle");
            // debug!(
            //     "Starting command handler task for user '{}'",
            //     identity_handle
            // );
            while let Some(command) = receiver.recv().await {
                debug!("Command handler received command: {:?}", command);

                // Forward the command to the state actor and await the reply
                match state_actor.ask(command).await {
                    Ok(reply) => {
                        debug!("State actor replied with: {}", reply);
                        match reply {
                            StateActorReply::ChatHandle(handle) => {
                                println!("Your current chat handle is: {}", handle);
                            }
                            StateActorReply::Status(result) => match result {
                                Ok(_) => println!("Command executed successfully."),
                                Err(e) => error!("Command processing failed with error: {:?}", e),
                            },
                            StateActorReply::Users(items) => todo!(),
                            StateActorReply::Channels(items) => todo!(),
                            StateActorReply::SafetyNumber(safety_number) => {
                                println!("{}", safety_number);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to send command to state actor: {}", e);
                        break;
                    }
                }
            }
        })
    }

    /// Spawn a task to continuously receive UDP multicast messages.
    pub fn spawn_udp_input_task(
        &self,
        state_actor: ActorRef<StateActor>,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);

        tokio::spawn(async move {
            debug!("Starting UDP input task to receive multicast messages");

            loop {
                match network_manager.receive_message().await {
                    Ok(packet) => {
                        debug!("Received network packet: {:?}", packet);

                        // TODO: Process the packet - forward to state actor or handle appropriately
                        // This is where you would integrate with state_actor to process incoming messages
                    }
                    Err(e) => {
                        error!("Error receiving network message: {}", e);
                        // Continue loop to keep receiving despite errors
                    }
                }
            }
        })
    }

    /// Display task for printing messages to console. This task is READ ONLY and does not send messages.
    pub fn spawn_message_display_task(
        &self,
        state_actor: ActorRef<StateActor>,
        mut receiver: tokio::sync::mpsc::Receiver<crate::agora_chat::PlaintextPayload>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            debug!("Starting message display task.");
            let chat_id = match state_actor.ask(Command::Nick { nickname: None }).await {
                Ok(StateActorReply::ChatHandle(handle)) => handle,
                Err(e) => {
                    error!("Unable to get chat handle: {}", e);
                    return;
                }
                _ => {
                    unreachable!("Expected ChatHandle reply")
                }
            };
            while let Some(message) = receiver.recv().await {
                if message.display_name != chat_id {
                    debug!(
                        "Chat processing received message from '{}' with content: '{}'",
                        message.display_name, message.content
                    );

                    eprint!("\r\x1b[K");
                    eprintln!(
                        "{} {}: {}",
                        message.timestamp, message.display_name, message.content
                    );
                    eprint!("{} > ", chat_id);
                } else {
                    debug!("Ignoring self-sent message from '{}'", message.display_name);
                }
            }
            debug!("Message display task ending.");
        })
    }
}
