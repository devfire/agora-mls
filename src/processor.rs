use kameo::prelude::ActorRef;

use parking_lot::Mutex; // for more efficient locking
use rustyline::{Editor, config::Builder, error::ReadlineError, history::DefaultHistory};
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    agora_chat::{UserAnnouncement, agora_packet},
    command::Command,
    crypto_identity_actor::{
        CryptoIdentityActor, CryptoIdentityMessage, CryptoIdentityReply, ProcessedMessageResult,
    },
    network,
    protobuf_wrapper::ProtoMlsMessageOut, // state_actor::{StateActor, StateActorMessage, StateActorReply},
};

use anyhow::{Context, anyhow};

pub struct Processor {
    pub network_manager: Arc<network::NetworkManager>,
    pub nick: String,

    // we can't access self directly inside the spawn_stdin_input_task blocking closure.
    // Why not?
    // The Technical Reason
    // When you use tokio::task::spawn_blocking(move || { ... }), you're creating a closure that:
    //
    // Must be 'static - The closure needs to potentially outlive the current scope because it's being moved to a separate blocking thread pool that Tokio manages
    // Takes ownership - The move keyword means the closure takes ownership of any variables it captures
    // The problem is that self in the method signature is a reference (&self), not owned data.
    // In Rust:
    // You can't move a borrowed reference into a 'static closure
    // The lifetime of &self is tied to the Processor instance, but the spawned thread might outlive that instance
    // Rust's borrow checker prevents this to ensure memory safety
    pub current_group: Arc<Mutex<Option<String>>>,
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
            current_group: Arc::new(Mutex::new(None)),
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

        // Remember: the nick is immutable for the duration of this task because it was passed as a parameter during the initialization of Processor.
        // And that came via -l from App config which is fixed for the app lifetime.
        let nick = self.nick.clone();

        let current_group = Arc::clone(&self.current_group);
        tokio::task::spawn_blocking(move || {
            // debug!("Starting stdin input task for agent '{}'", handle);

            let config = Builder::new().auto_add_history(true).build();

            let mut rustyline_editor =
                match Editor::<crate::command::CommandCompleter, DefaultHistory>::with_config(
                    config,
                ) {
                    Ok(mut editor) => {
                        editor.set_helper(Some(crate::command::CommandCompleter));
                        editor
                    }
                    Err(e) => {
                        error!("Unable to initialize the rustyline editor {e}");
                        return;
                    }
                };

            // let mut printer = match rustyline_editor.create_external_printer() {
            //     Ok(p) => p,
            //     Err(e) => {
            //         error!("Unable to create rustyline external printer: {e}");
            //         return;
            //     }
            // };
            // This just fans out commands & messages to the respective handlers very fast.
            // Replies either go to the display or to the network outbound.
            loop {
                // Build prompt with group indicator
                let prompt = {
                    // NOTE:  The unwrap() on a mutex lock can panic if the mutex is "poisoned" (a thread panicked while holding the lock).
                    // However, parking_lot's Mutex lock method does not return a Result, it directly returns the lock guard.
                    // This means that if a thread panics while holding the lock, other threads trying to acquire the lock will not panic,
                    // but will instead block until the lock is available.
                    let group = current_group.lock(); // parking lot! 
                    if let Some(ref g) = *group {
                        format!("\x1b[36m[{}]\x1b[0m {} > ", g, nick)
                    } else {
                        format!("{} > ", nick)
                    }
                };
                let readline = rustyline_editor.readline(&prompt);

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
                                        error!("Command processing failed with {e}");
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
    pub fn spawn_ui_input_handler_task(
        &self,
        crypto_actor: ActorRef<CryptoIdentityActor>,
        mut receiver: tokio::sync::mpsc::Receiver<String>,
        message_sender: tokio::sync::mpsc::Sender<String>,
        display_sender: tokio::sync::mpsc::Sender<String>,
    ) -> tokio::task::JoinHandle<()> {
        let network_manager = self.network_manager.clone();
        let current_group = Arc::clone(&self.current_group);
        tokio::spawn(async move {
            debug!("Starting message handler task.");

            while let Some(message) = receiver.recv().await {
                debug!("Message handler received: {:?}", message);

                // NOTE: We must extract the value and drop the lock BEFORE any .await points
                // to ensure the future is Send-safe. parking_lot::Mutex guards are not Send.
                let group_name = {
                    let group = current_group.lock();
                    (*group).clone() // Clone the Option<String>
                }; // Lock is dropped here

                // Check if we have a group outside the lock scope
                let group_name = if let Some(name) = group_name {
                    name
                } else {
                    let err_msg = "No active group selected. Use /group <group_name> to select a group before sending messages.";

                    if let Err(e) = message_sender.send(err_msg.to_string()).await {
                        error!("Unable to send an update from spawn_ui_input_handler_task {e}.");
                    }
                    continue;
                };
                // Send to the state actor for encryption and multicast
                match crypto_actor
                    .ask(CryptoIdentityMessage::EncryptMessage {
                        plaintext: message.into(),
                        group_name: group_name.clone(),
                    })
                    .await
                {
                    Ok(reply) => {
                        if let Err(e) = Self::handle_crypto_identity_reply(
                            reply,
                            &display_sender,
                            &network_manager,
                            &current_group,
                        )
                        .await
                        {
                            display_sender
                                .send(format!("{e}"))
                                .await
                                .unwrap_or_else(|e| {
                                    error!("Unable to send the error msg to display: {e}")
                                });
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
        let current_group = Arc::clone(&self.current_group);

        tokio::spawn(async move {
            debug!("Starting command handler task.");
            while let Some(command) = receiver.recv().await {
                debug!("Command handler received command: {:?}", command);

                // Update local state for UI when switching groups or creating a group
                if let Command::Group { ref group_name } | Command::CreateGroup { ref group_name } =
                    command
                {
                    let mut group = current_group.lock();
                    *group = Some(group_name.clone());
                    println!("\x1b[32m✓ Switched to group: {}\x1b[0m", group_name);
                }

                // OK, now we can proceed.
                if let Some(c) = command.to_crypto_message() {
                    // Forward the command to the state actor and await the reply
                    match crypto_actor.ask(c).await {
                        Ok(reply) => {
                            if let Err(e) = Self::handle_crypto_identity_reply(
                                reply,
                                &display_sender,
                                &network_manager,
                                &current_group,
                            )
                            .await
                            {
                                debug!("Failed to handle crypto identity reply: {}", e);
                                display_sender
                                    .send(format!("{e}"))
                                    .await
                                    .unwrap_or_else(|e| {
                                        error!("Unable to send the msg to display: {e}")
                                    });
                            }
                        }
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
        let current_group = Arc::clone(&self.current_group);

        tokio::spawn(async move {
            debug!("Starting UDP input task to receive multicast messages");

            let mut recv_buf = vec![0u8; network_manager.buffer_size()];

            loop {
                match network_manager.receive_message(&mut recv_buf).await {
                    Ok(packet) => {
                        // Handle different message types
                        match &packet.0.0.body {
                            Some(agora_packet::Body::UserAnnouncement(user_announcement)) => {
                                if let Err(e) = Self::handle_network_user_announcement(
                                    user_announcement,
                                    &crypto_actor,
                                    &display_sender,
                                    &network_manager,
                                    &current_group,
                                )
                                .await
                                {
                                    error!("Failed to process NetworkUserAnnouncement: {}", e);
                                };
                            }
                            Some(agora_packet::Body::EncryptedGroupInfo(encrypted_group_info)) => {
                                if let Err(e) = Self::handle_encrypted_group_info(
                                    &crypto_actor,
                                    &display_sender,
                                    &network_manager,
                                    &current_group,
                                    encrypted_group_info,
                                )
                                .await
                                {
                                    error!("Failed to process EncryptedGroupInfo: {}", e);
                                }
                            }
                            _ => {
                                // All other messages (PublicMessage, PrivateMessage, Welcome, GroupInfo)
                                // go to the crypto actor as MlsMessageIn
                                let mls_message_in = if let Ok(msg) = packet.0.try_into() {
                                    msg
                                } else {
                                    error!("Received invalid MlsMessageIn packet");
                                    continue;
                                };

                                match crypto_actor
                                    .ask(CryptoIdentityMessage::ProcessMessage { mls_message_in })
                                    .await
                                {
                                    Ok(reply) => {
                                        if let Err(e) = Self::handle_crypto_identity_reply(
                                            reply,
                                            &display_sender,
                                            &network_manager,
                                            &current_group,
                                        )
                                        .await
                                        {
                                            // Typically, these errors are because we received a msg for an unknown group,
                                            // so we just quietly debug log and move on
                                            debug!("Error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        display_sender.send(format!("{e}")).await.unwrap_or_else(
                                            |e| {
                                                error!(
                                                    "Unable to send the error msg to display: {e}"
                                                )
                                            },
                                        );
                                    }
                                }
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
        let current_group = Arc::clone(&self.current_group);

        tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                eprint!("\r\x1b[K");
                eprintln!("{message}");

                // Print the correct prompt with current group
                let prompt = {
                    let group = current_group.lock();
                    match &*group {
                        Some(g) => format!("\x1b[36m[{}]\x1b[0m {} > ", g, nick),
                        None => format!("{} > ", nick),
                    }
                };
                eprint!("{}", prompt);
            }
        })
    }

    async fn handle_network_user_announcement(
        user_announcement: &UserAnnouncement,
        crypto_actor: &ActorRef<CryptoIdentityActor>,
        display_sender: &tokio::sync::mpsc::Sender<String>,
        network_manager: &Arc<network::NetworkManager>,
        current_group: &Arc<Mutex<Option<String>>>,
    ) -> anyhow::Result<()> {
        debug!(
            "Received UserAnnouncement from: {}",
            user_announcement.username
        );

        // send it to the crypto actor as a UserAnnouncement
        match crypto_actor
            .ask(CryptoIdentityMessage::AddNewUser {
                user_announcement: user_announcement.clone(),
            })
            .await
        {
            Ok(reply) => {
                Self::handle_crypto_identity_reply(
                    reply,
                    display_sender,
                    network_manager,
                    current_group,
                )
                .await?;
                Ok(())
            }

            Err(e) => Err(anyhow!("{e}")),
        }
    }

    async fn handle_encrypted_group_info(
        crypto_actor: &ActorRef<CryptoIdentityActor>,
        display_sender: &tokio::sync::mpsc::Sender<String>,
        network_manager: &Arc<network::NetworkManager>,
        current_group: &Arc<Mutex<Option<String>>>,
        encrypted_group_info: &crate::agora_chat::EncryptedGroupInfo,
    ) -> anyhow::Result<()> {
        if !encrypted_group_info.sender_username.is_empty() {
            display_sender
                .send(format!(
                    "Received group invitation from {}",
                    encrypted_group_info.sender_username
                ))
                .await?;

            // Store the sender's KeyPackage so we can message them back
            if !encrypted_group_info.sender_key_package.is_empty() {
                let sender_announcement = UserAnnouncement {
                    username: encrypted_group_info.sender_username.clone(),
                    tls_serialized_key_package: encrypted_group_info.sender_key_package.clone(),
                };

                Self::handle_network_user_announcement(
                    &sender_announcement,
                    crypto_actor,
                    display_sender,
                    network_manager,
                    current_group,
                )
                .await?;
            }
        }
        match crypto_actor
            .ask(CryptoIdentityMessage::ProcessEncryptedGroupInfo {
                encrypted_group_info: encrypted_group_info.clone(),
            })
            .await
        {
            Ok(reply) => {
                Self::handle_crypto_identity_reply(
                    reply,
                    display_sender,
                    network_manager,
                    current_group,
                )
                .await?
            }
            Err(e) => {
                display_sender.send(e.to_string()).await?;
                return Err(anyhow!("Failed to process EncryptedGroupInfo: {}", e));
            }
        }

        display_sender
            .send(format!(
                "Received HPKE-encrypted GroupInfo for external commit join."
            ))
            .await?;
        Ok(())
    }

    async fn handle_crypto_identity_reply(
        reply: CryptoIdentityReply,
        display_sender: &tokio::sync::mpsc::Sender<String>,
        network_manager: &Arc<network::NetworkManager>,
        current_group: &Arc<Mutex<Option<String>>>,
    ) -> anyhow::Result<()> {
        match reply {
            CryptoIdentityReply::Success(message) => {
                display_sender
                    .send(message)
                    .await
                    .context("Unable to send success message to display")?;
                Ok(())
            }
            CryptoIdentityReply::Failure(error) => Err(anyhow!("{error}")),
            CryptoIdentityReply::GroupCreated(group_name) => {
                display_sender
                    .send(format!("Group {group_name} created"))
                    .await?;
                Ok(())
            }
            CryptoIdentityReply::EncryptedGroupInfoForExternalInvite {
                encrypted_group_info,
            } => {
                // HPKE-encrypted GroupInfo for external commit join
                // Send to network for the external joiner
                network_manager
                    .send_message(crate::protobuf_wrapper::ProtoMlsMessageOut(
                        encrypted_group_info,
                    ))
                    .await?;

                display_sender
                    .send("Encrypted GroupInfo sent for external commit join".to_string())
                    .await?;
                Ok(())
            }
            CryptoIdentityReply::MlsMessageOut(mls_message_out) => {
                let msg: ProtoMlsMessageOut = mls_message_out
                    .try_into()
                    .context("Failed to convert MlsMessageOut")?;

                network_manager
                    .send_message(msg)
                    .await
                    .context("Failed to send message over network")?;

                Ok(())
            }
            CryptoIdentityReply::MessageProcessed { result } => {
                // let's see what we got
                match result {
                    ProcessedMessageResult::ApplicationMessage(m) => {
                        display_sender.send(m).await?;
                        Ok(())
                    }

                    ProcessedMessageResult::StagedCommitMerged => {
                        display_sender
                            .send(format!("Staged commit merged successfully."))
                            .await?;
                        Ok(())
                    }
                }
            }
            CryptoIdentityReply::GroupJoined { group_name } => {
                display_sender
                    .send(format!("Group {group_name} joined successfully"))
                    .await?;
                Ok(())
            }
            CryptoIdentityReply::Groups { groups } => {
                let group_list = groups.join(", ");
                display_sender
                    .send(format!("Known groups: {group_list}"))
                    .await?;
                Ok(())
            }
            CryptoIdentityReply::Users { users } => {
                let user_list = users.join(", ");
                display_sender
                    .send(format!("Known users: {user_list}"))
                    .await?;
                Ok(())
            }
            CryptoIdentityReply::UserAnnouncement(agora_packet) => {
                network_manager
                    .send_message(crate::protobuf_wrapper::ProtoMlsMessageOut(agora_packet))
                    .await?;

                display_sender
                    .send(format!("User announcement sent successfully"))
                    .await?;
                Ok(())
            }

            CryptoIdentityReply::ExternalCommitCreated {
                commit_message,
                group_name,
            } => {
                let msg = commit_message.try_into()?;

                network_manager.send_message(msg).await?;

                // update the current group
                // NOTE: The curly braces are important to limit the scope of the lock
                {
                    let mut group = current_group.lock();
                    *group = Some(group_name);
                }
                display_sender
                    .send("Sent external commit to group members.".to_string())
                    .await?;
                Ok(())
            }
            CryptoIdentityReply::SafetyNumber(safety_number) => {
                display_sender
                    .send(format!("Your safety number:\n{}", safety_number))
                    .await?;
                Ok(())
            }
        }
    }
}
