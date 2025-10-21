use kameo::prelude::ActorRef;

use openmls::prelude::{KeyPackageIn, tls_codec::Deserialize};
use rustyline::{DefaultEditor, error::ReadlineError};
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    command::Command,
    crypto_identity_actor::{CryptoIdentityActor, CryptoIdentityMessage, CryptoIdentityReply},
    network, // state_actor::{StateActor, StateActorMessage, StateActorReply},
};

pub struct Processor {
    pub network_manager: Arc<network::NetworkManager>,
    pub nick: String,
}

impl Processor {
    pub fn new(
        // state_actor: ActorRef<StateActor>,
        // identity: MyIdentity,
        nick: String,
        network_manager: Arc<network::NetworkManager>,
    ) -> Self {
        Self {
            network_manager,
            nick,
        }
    }

    /// Spawn a task to handle user input from stdin.
    pub fn spawn_stdin_input_task(
        &self,
        command_sender: tokio::sync::mpsc::Sender<Command>,
        message_sender: tokio::sync::mpsc::Sender<String>,
        display_sender: tokio::sync::mpsc::Sender<String>,
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
        let nick = self.nick.clone();
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
                let readline = rustyline_editor.readline(&format!("{} > ", nick));

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
                                        if display_sender.blocking_send(e.to_string()).is_err() {
                                            error!(
                                                "Unable to send error from spawn_stdin_input_task"
                                            );
                                        }
                                        continue;
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
        crypto_actor: ActorRef<CryptoIdentityActor>,
        mut receiver: tokio::sync::mpsc::Receiver<String>,
        message_sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = self.network_manager.clone();
        tokio::spawn(async move {
            debug!("Starting message handler task.");

            while let Some(message) = receiver.recv().await {
                debug!("Message handler received: {:?}", message);

                // Send to the state actor for encryption and multicast
                match crypto_actor
                    .ask(CryptoIdentityMessage::EncryptMessage(message.into()))
                    .await
                {
                    Ok(reply) => {
                        debug!("Message dispatched successfully.");
                        match reply {
                            CryptoIdentityReply::Failure(e) => {
                                debug!("ERROR: {e}");
                                message_sender.send(e.to_string()).await.expect(
                                    "Unable to send an update from spawn_message_handler_task.",
                                );
                            }

                            CryptoIdentityReply::MlsMessageOut(mls_msg_out) => {
                                let proto_mls_msg = if let Ok(msg) = mls_msg_out.try_into() {
                                    msg
                                } else {
                                    error!("Received invalid MlsMessageIn packet");
                                    continue;
                                };

                                if let Err(e) = network_manager.send_message(proto_mls_msg).await {
                                    error!("Failed to send message over network: {}", e);
                                }
                            }
                            // a response to state_actor.ask(StateActorMessage::Encrypt(message)) is either an StateActorReply::EncryptedMessage or an error
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

    /// We need this because spawn_stdin_input_task cannot send messages directly to the state actor which requires .await.
    pub fn spawn_command_handler_task(
        &self,
        crypto_actor: ActorRef<CryptoIdentityActor>,
        mut receiver: tokio::sync::mpsc::Receiver<Command>,
        display_sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        // let identity_handle = self.identity.handle.clone();
        let network_manager = Arc::clone(&self.network_manager);
        tokio::spawn(async move {
            debug!("Starting command handler task.");
            while let Some(command) = receiver.recv().await {
                debug!("Command handler received command: {:?}", command);

                // The flow is like is:
                // 1. User types in command in stdin_input_task via rustyline
                // 2. Input is converted to Command and sent to command_handler_task via channel
                // 3. command.to_crypto_message() converts Command to CryptoIdentityMessage. This is needed because not all command map to crypto actions.
                // 4. command_handler_task sends CryptoIdentityMessage to crypto_actor and awaits reply
                // 5. command_handler_task processes CryptoIdentityReply and takes appropriate action
                if let Some(c) = command.to_crypto_message() {
                    // Forward the command to the state actor and await the reply
                    match crypto_actor.ask(c).await {
                        Ok(reply) => match reply {
                            CryptoIdentityReply::UpdateComplete => todo!(),
                            CryptoIdentityReply::GroupCreated(group_name) => {
                                                        display_sender
                                                            .send(format!("Group {group_name} created"))
                                                            .await
                                                            .expect("Unable to send the decrypted msg to display");
                                                    }
                            CryptoIdentityReply::WelcomePackage {
                                                        commit,
                                                        welcome,
                                                        group_info,
                                                    } => {
                                                        // The CryptoIdentityReply::MemberAdded returns the tuple (MlsMessageOut, Welcome, Option<GroupInfo>).
                                                        // The MlsMessageOut contains a Commit message that needs to be fanned out to existing group members.
                                                        // The Welcome message must be sent to the newly added members, along the optional GroupInfo if it is available.
                                                        let _gi = group_info; // currently unused

                                                        let commit_msg = if let Ok(msg) = commit.try_into() {
                                                            msg
                                                        } else {
                                                            error!("Received invalid MlsMessageIn packet");
                                                            continue;
                                                        };
                                                        if let Err(e) = network_manager.send_message(commit_msg).await {
                                                            error!("Failed to send message over network: {}", e);
                                                        }

                                                        match welcome.try_into() {
                                                            Ok(welcome_msg) => {
                                                                if let Err(e) = network_manager.send_message(welcome_msg).await {
                                                                    error!("Failed to send welcome message: {}", e);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to convert welcome message: {}", e);
                                                            }
                                                        }
                                                        // TODO: need to figure out how to send group info properly
                                                        // if let Some(group_info) = group_info {
                                                        //     let group_info_msg = group_info.try_into().expect("boo");
                                                        //     if let Err(e) =
                                                        //         network_manager.send_message(group_info_msg).await
                                                        //     {
                                                        //         error!("Failed to send message over network: {}", e);
                                                        //     }
                                                        // }
                                                    }
                            CryptoIdentityReply::MlsMessageOut(mls_message_out) => {
                                                        let msg = mls_message_out.try_into().expect("boo");

                                                        if let Err(e) = network_manager.send_message(msg).await {
                                                            error!("Failed to send message over network: {}", e);
                                                        }
                                                    }
                            CryptoIdentityReply::MessageProcessed { result } => {
                                                        match result {
                                                            crate::crypto_identity_actor::ProcessedMessageResult::ApplicationMessage(_) => todo!(),
                                                            crate::crypto_identity_actor::ProcessedMessageResult::ProposalMessage => todo!(),
                                                            crate::crypto_identity_actor::ProcessedMessageResult::ExternalJoinProposal => todo!(),
                                                            crate::crypto_identity_actor::ProcessedMessageResult::StagedCommitMerged => todo!(),
                                                        }

                                                    }
                            CryptoIdentityReply::GroupJoined { group_name } => {
                                                        display_sender
                                                            .send(format!("Group {group_name} joined successfully"))
                                                            .await
                                                            .expect("Unable to send the decrypted msg to display");
                                                    }
                            CryptoIdentityReply::Groups { groups } => {
                                                        let group_list = groups.join(", ");
                                                        display_sender
                                                            .send(format!("Known groups: {group_list}"))
                                                            .await
                                                            .expect("Unable to send the decrypted msg to display");
                                                    }
                            CryptoIdentityReply::ActiveGroup { group_name } => {
                                                        let active_group_name = group_name.unwrap_or("No active group".to_string());

                                                        display_sender
                                                            .send(format!("Current active group: {active_group_name} "))
                                                            .await
                                                            .expect("Unable to send the decrypted msg to display");
                                                    },
                            CryptoIdentityReply::Success => {
                                display_sender
                                                            .send("Command executed successfully.".to_string())
                                                            .await
                                                            .expect("Unable to send the decrypted msg to display");
                            },
                            CryptoIdentityReply::Failure(error) => {
                                display_sender
                                                            .send(format!("Command failed {error} "))
                                                            .await
                                                            .expect("Unable to send the decrypted msg to display");
                            },
                            CryptoIdentityReply::UserAnnouncement(announcement) => {

                                 if let Err(e) = network_manager
                                        .send_message(crate::protobuf_wrapper::ProtoMlsMessageOut(
                                            announcement,
                                        ))
                                        .await
                                    {
                                        error!(
                                            "Failed to send user announcement over network: {}",
                                            e
                                        );
                                    }
                                },
                        },
                        Err(e) => {
                            error!("Failed to send command to state actor: {}", e);
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Spawn a task to continuously receive UDP multicast messages.
    pub fn spawn_udp_input_task(
        &self,
        crypto_actor: ActorRef<CryptoIdentityActor>,
        display_sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = Arc::clone(&self.network_manager);

        tokio::spawn(async move {
            debug!("Starting UDP input task to receive multicast messages");

            loop {
                match network_manager.receive_message().await {
                    Ok(packet) => {
                        // Determine if the message is a user announcement or an MLS message
                        if let Some(crate::agora_chat::agora_packet::Body::UserAnnouncement(
                            user_announcement,
                        )) = &packet.0.body
                        {
                            debug!(
                                "Received UserAnnouncement from: {}",
                                user_announcement.username
                            );

                            // // Deserialize the KeyPackage from the announcement
                            // let key_package_in = KeyPackageIn::tls_deserialize(
                            //     &mut &user_announcement.tls_serialized_key_package[..],
                            // )
                            // .expect("boo");

                            // send it to the crypto actor as a UserAnnouncement
                            match crypto_actor
                                .ask(CryptoIdentityMessage::AddNewUser {
                                    user_announcement: user_announcement.clone(),
                                })
                                .await
                            {
                                Ok(reply) => match reply {
                                    CryptoIdentityReply::Success => {
                                        display_sender
                                            .send(format!(
                                                "Processed UserAnnouncement from {}",
                                                user_announcement.username
                                            ))
                                            .await
                                            .expect("Unable to send the decrypted msg to display");
                                    }
                                    CryptoIdentityReply::Failure(e) => {
                                        error!("Failed to process new UserAnnouncement: {e}");
                                    }
                                    _ => unreachable!("Pack it up boys. We are done here."),
                                },
                                Err(e) => {
                                    display_sender
                                        .send(e.to_string())
                                        .await
                                        .expect("Unable to send the error msg to display");
                                }
                            }
                        }
                        // User announcements are handled above, other messages go to the crypto actor as MlsMessageIn
                        let mls_message_in = if let Ok(msg) = packet.try_into() {
                            msg
                        } else {
                            error!("Received invalid MlsMessageIn packet");
                            continue;
                        };

                        match crypto_actor
                            .ask(CryptoIdentityMessage::ProcessMessage { mls_message_in })
                            .await
                        {
                            Ok(reply) => match reply {
                                CryptoIdentityReply::UpdateComplete => todo!(),
                                CryptoIdentityReply::GroupCreated(_) => todo!(),
                                CryptoIdentityReply::WelcomePackage {
                                    commit,
                                    welcome,
                                    group_info,
                                } => todo!(),
                                CryptoIdentityReply::MlsMessageOut(mls_message_out) => todo!(),
                                CryptoIdentityReply::MessageProcessed { result } => todo!(),
                                CryptoIdentityReply::GroupJoined { group_name } => todo!(),
                                CryptoIdentityReply::Groups { groups } => todo!(),
                                CryptoIdentityReply::ActiveGroup { group_name } => todo!(),
                                CryptoIdentityReply::Success => todo!(),
                                CryptoIdentityReply::Failure(error) => todo!(),
                                CryptoIdentityReply::UserAnnouncement(announcement) => {}
                            },
                            Err(e) => {
                                display_sender
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
        mut receiver: tokio::sync::mpsc::Receiver<String>,
    ) -> tokio::task::JoinHandle<()> {
        let nick = self.nick.clone();
        tokio::spawn(async move {
            debug!("Starting message display task.");

            while let Some(message) = receiver.recv().await {
                eprint!("\r\x1b[K");
                eprintln!("{message}");
                // eprintln!(
                //     "{} {}: {}",
                //     message.timestamp, message.display_name, message.content
                // );
                eprint!("{} > ", nick);
            }
            debug!("Message display task ending.");
        })
    }
}
