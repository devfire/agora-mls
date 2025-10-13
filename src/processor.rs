use kameo::prelude::ActorRef;

use rustyline::{DefaultEditor, error::ReadlineError};
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    command::Command,
    network,
    state_actor::{StateActor, StateActorMessage, StateActorReply},
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
        command_sender: tokio::sync::mpsc::Sender<Command>,
        message_sender: tokio::sync::mpsc::Sender<String>,
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

            // This just fans out commands & messages to the respective handlers very fast.
            // Replies either go to the display or to the network outbound
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

                                    // Use blocking_send since we're in a blocking context
                                    if command_sender.blocking_send(c).is_err() {
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
                                        debug!("Command processing failed with {e}");
                                        if message_sender.blocking_send(e.to_string()).is_err() {
                                            error!(
                                                "Unable to send error from spawn_stdin_input_task"
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        // end of if line.starts_with('/')
                        else {
                            // not a command, we need to encrypt & ship the msg
                            if message_sender.blocking_send(line).is_err() {
                                error!(
                                    "Failed to send message: spawn_message_handler_task receiver has been dropped."
                                );
                                break;
                            }
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

    /// Spawn a task to handle messages from stdin and forward them to the network manager.
    pub fn spawn_message_handler_task(
        &self,
        state_actor: ActorRef<StateActor>,
        mut receiver: tokio::sync::mpsc::Receiver<String>,
        message_sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = self.network_manager.clone();
        tokio::spawn(async move {
            debug!("Starting message handler task.");

            while let Some(message) = receiver.recv().await {
                debug!("Message handler received: {:?}", message);

                // Send to the state actor for encryption and multicast
                match state_actor.ask(StateActorMessage::Encrypt(message)).await {
                    Ok(reply) => {
                        debug!("Message dispatched successfully.");
                        match reply {
                            StateActorReply::Status(s) => match s {
                                // We'll never hit a Status Ok because an Ok result simply a StateActorReply::EncryptedMessage
                                Ok(_) => unreachable!(),

                                // However, errors we may encounter, yes.
                                Err(e) => {
                                    debug!("ERROR: {e}");
                                    message_sender.send(e.to_string()).await.expect(
                                        "Unable to send an update from spawn_message_handler_task.",
                                    );
                                }
                            },
                            StateActorReply::EncryptedMessage(proto_mls_msg_out) => {
                                // Send the packet over the network
                                if let Err(e) =
                                    network_manager.send_message(proto_mls_msg_out).await
                                {
                                    error!("Failed to send message over network: {}", e);
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    Err(e) => {
                        error!(
                            "Something horrible happened with the spawn_message_handler_task(): {e} "
                        )
                    }
                }
            }
        })
    }

    pub fn spawn_command_handler_task(
        &self,
        state_actor: ActorRef<StateActor>,
        mut receiver: tokio::sync::mpsc::Receiver<Command>,
        message_sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        // let identity_handle = self.identity.handle.clone();
        tokio::spawn(async move {
            debug!("Starting command handler task.");
            while let Some(command) = receiver.recv().await {
                debug!("Command handler received command: {:?}", command);

                // Forward the command to the state actor and await the reply
                match state_actor.ask(StateActorMessage::Command(command)).await {
                    Ok(reply) => {
                        match reply {
                            StateActorReply::ChatHandle(handle) => {
                                message_sender.send(handle).await.expect(
                                    "Unable to send chat handle from spawn_command_handler_task",
                                );
                            }
                            StateActorReply::Status(result) => match result {
                                Ok(_) => debug!("Command executed successfully."),
                                Err(e) => {
                                    debug!("Command processing failed with error: {:?}", e);
                                    message_sender.send(e.to_string()).await.expect(
                                        "Unable to send an update from spawn_command_handler_task",
                                    );
                                }
                            },
                            StateActorReply::Groups(groups) => {
                                let my_groups = if let Some(groups) = groups {
                                    groups.join(" ")
                                } else {
                                    String::from("No groups created.")
                                };
                                message_sender.send(my_groups).await.expect(
                                    "Unable to send groups from spawn_command_handler_task",
                                );
                            }
                            StateActorReply::SafetyNumber(safety_number) => {
                                message_sender.send(safety_number.to_string()).await.expect(
                                    "Unable to send safety_number from spawn_command_handler_task",
                                );
                            }
                            StateActorReply::ActiveGroup(mls_group) => {
                                let active_group = if let Some(active_group) = mls_group {
                                    debug!("Active group: {active_group}");
                                    active_group
                                } else {
                                    debug!("No active group");
                                    crate::error::StateActorError::NoActiveGroup.to_string()
                                };
                                message_sender.send(active_group).await.expect(
                                    "Unable to send responses from spawn_command_handler_task",
                                );
                            }
                            _ => {
                                unreachable!("We'll never return a msg to a command")
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
        message_sender: tokio::sync::mpsc::Sender<String>,
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

                        match state_actor.ask(StateActorMessage::Decrypt(packet)).await {
                            Ok(reply) => match reply {
                                StateActorReply::DecryptedMessage(message) => {
                                    message_sender
                                        .send(message)
                                        .await
                                        .expect("Unable to send the decrypted msg to display");
                                }
                                StateActorReply::Status(s) => match s {
                                    Ok(_) => unreachable!(),
                                    Err(e) => {
                                        message_sender
                                            .send(e.to_string())
                                            .await
                                            .expect("Unable to send the error msg to display");
                                    }
                                },
                                _ => unreachable!(),
                            },
                            Err(e) => {
                                message_sender
                                    .send(e.to_string())
                                    .await
                                    .expect("Unable to send the error msg to display");
                            }
                        }
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
        mut receiver: tokio::sync::mpsc::Receiver<String>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            debug!("Starting message display task.");
            let chat_id = match state_actor
                .ask(StateActorMessage::Command(Command::Nick { nickname: None }))
                .await
            {
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
                eprint!("\r\x1b[K");
                eprintln!("{message}");
                // eprintln!(
                //     "{} {}: {}",
                //     message.timestamp, message.display_name, message.content
                // );
                eprint!("{} > ", chat_id);
            }
            debug!("Message display task ending.");
        })
    }
}
