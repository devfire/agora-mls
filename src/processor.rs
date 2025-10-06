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

            // The problem here is that spawn_blocking runs on a separate thread pool that doesn't have access to the async runtime,
            // so we can't use .await directly inside it.
            // Therefore, tokio::runtime::Handle::current().block_on() is to bridge the gap between the blocking and async contexts.
            let rt = tokio::runtime::Handle::current();
            let identity_handle = rt.block_on(async {
                match state_actor
                    .ask(Command::Nick { nickname: None })
                    .await
                    .expect("Unable to get chat handle")
                {
                    StateActorReply::ChatHandle(handle) => handle,
                    _ => panic!("Expected ChatHandle reply"),
                }
            });
            loop {
                let readline = rustyline_editor.readline(&format!("{} > ", identity_handle));

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
                        else {
                            debug!("Sending message to network manager for broadcast: {}", line);
                            // Here we would create a ChatPacket and send it via the network manager
                            // For now, just log the message
                            // let packet = ChatPacket::new_message(&identity_handle, &line);
                            // if let Err(e) = self.network_manager.send_message(packet).await {
                            //     error!("Failed to send message: {}", e);
                            // }
                        }
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

    // // /// Display task for printing messages to console. This task is READ ONLY and does not send messages.
    // pub fn spawn_message_display_task(
    //     &self,
    //     mut receiver: tokio::sync::mpsc::Receiver<PlaintextPayload>,
    //     chat_id: &str,
    // ) -> tokio::task::JoinHandle<()> {
    //     let chat_id = chat_id.to_string();

    //     tokio::spawn(async move {
    //         debug!("Starting chat processing task for agent '{}'", chat_id);
    //         while let Some(message) = receiver.recv().await {
    //             if message.display_name != chat_id {
    //                 debug!(
    //                     "Chat processing received message from '{}' with content: '{}'",
    //                     message.display_name, message.content
    //                 );

    //                 eprint!("\r\x1b[K");
    //                 eprintln!(
    //                     "{} {}: {}",
    //                     message.timestamp, message.display_name, message.content
    //                 );
    //                 eprint!("{} > ", chat_id);
    //             } else {
    //                 debug!("Ignoring self-sent message from '{}'", message.display_name);
    //             }
    //         }
    //         debug!("Message display task ending.");
    //     })
    // }
}
