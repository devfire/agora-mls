use kameo::prelude::ActorRef;

use parking_lot::Mutex; // for more efficient locking
use rustyline::{Editor, config::Builder, error::ReadlineError, history::DefaultHistory};
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    agora_chat::UserAnnouncement,
    command::Command,
    crypto_identity_actor::{
        CryptoIdentityActor, CryptoIdentityMessage, CryptoIdentityReply, ProcessedMessageResult,
    },
    error::CryptoIdentityActorError,
    network, // state_actor::{StateActor, StateActorMessage, StateActorReply},
};

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
        let current_group = Arc::clone(&self.current_group);

        tokio::spawn(async move {
            debug!("Starting command handler task.");
            while let Some(command) = receiver.recv().await {
                debug!("Command handler received command: {:?}", command);

                // Update local state for UI when switching groups
                if let Command::Group { ref name } = command {
                    let mut group = current_group.lock();
                    *group = Some(name.clone());
                    println!("\x1b[32m✓ Switched to group: {}\x1b[0m", name);
                }

                // Also update when creating a group
                if let Command::CreateGroup { ref name } = command {
                    let mut group = current_group.lock();
                    *group = Some(name.clone());
                }

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
                            CryptoIdentityReply::GroupCreated(group_name) => {
                                display_sender
                                    .send(format!("Group {group_name} created"))
                                    .await
                                    .expect("Unable to send the decrypted msg to display");
                            }

                            CryptoIdentityReply::EncryptedGroupInfoForExternalInvite {
                                encrypted_group_info,
                            } => {
                                // HPKE-encrypted GroupInfo for external commit join
                                // Send to network for the external joiner
                                if let Err(e) = network_manager
                                    .send_message(crate::protobuf_wrapper::ProtoMlsMessageOut(
                                        encrypted_group_info,
                                    ))
                                    .await
                                {
                                    error!(
                                        "Failed to send encrypted GroupInfo over network: {}",
                                        e
                                    );
                                } else {
                                    if let Err(e) = display_sender
                                        .send("HPKE-encrypted GroupInfo sent for external commit join".to_string())
                                        .await {
                                            error!("Unable to send status message to display: {e}");
                                        }
                                }
                            }
                            CryptoIdentityReply::MlsMessageOut(mls_message_out) => {
                                let msg = if let Ok(msg) = mls_message_out.try_into() {
                                    msg
                                } else {
                                    error!("Received invalid MlsMessageOut packet");
                                    continue;
                                };

                                if let Err(e) = network_manager.send_message(msg).await {
                                    error!("Failed to send message over network: {}", e);
                                }
                            }
                            CryptoIdentityReply::MessageProcessed { result } => match result {
                                ProcessedMessageResult::ApplicationMessage(msg) => {
                                    // Application message already decrypted
                                    if let Err(e) = display_sender.send(msg).await {
                                        error!("Unable to send decrypted message to display: {e}");
                                    }
                                }
                                _ => {
                                    // Regular proposal received and queued
                                    error!("Unexpected message in command handler task");
                                }
                            },
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
                            CryptoIdentityReply::CurrentGroup { group_name } => {
                                let active_group_name =
                                    group_name.unwrap_or("No active group".to_string());

                                display_sender
                                    .send(format!("Current active group: {active_group_name} "))
                                    .await
                                    .expect("Unable to send the decrypted msg to display");
                            }
                            CryptoIdentityReply::Success => {
                                display_sender
                                    .send("Command executed successfully.".to_string())
                                    .await
                                    .expect("Unable to send the decrypted msg to display");
                            }
                            CryptoIdentityReply::Failure(error) => {
                                if let Err(e) = display_sender
                                    .send(format!("Command failed: {error}"))
                                    .await
                                {
                                    error!("Unable to send error message: {e}");
                                }
                            }
                            CryptoIdentityReply::UserAnnouncement(announcement) => {
                                if let Err(e) = network_manager
                                    .send_message(crate::protobuf_wrapper::ProtoMlsMessageOut(
                                        announcement,
                                    ))
                                    .await
                                {
                                    error!("Failed to send User announcement over network: {}", e);
                                } else {
                                    if let Err(e) = display_sender
                                        .send(format!("User announcement sent successfully"))
                                        .await
                                    {
                                        error!("Unable to send error message: {e}");
                                    }
                                }
                            }
                            CryptoIdentityReply::Users { users } => {
                                let user_list = users.join(", ");
                                if let Err(e) = display_sender
                                    .send(format!("Known users: {user_list}"))
                                    .await
                                {
                                    error!("Unable to send the list of users to display: {e}");
                                }
                            }
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
                        // Handle different message types
                        match &packet.0.body {
                            Some(crate::agora_chat::agora_packet::Body::UserAnnouncement(
                                user_announcement,
                            )) => {
                                Self::handle_network_user_announcement(
                                    user_announcement,
                                    crypto_actor.clone(),
                                    display_sender.clone(),
                                )
                                .await;
                            }
                            Some(crate::agora_chat::agora_packet::Body::EncryptedGroupInfo(
                                encrypted_group_info,
                            )) => {
                                // Received HPKE-encrypted GroupInfo for external commit join
                                let sender_info = if !encrypted_group_info.sender_username.is_empty() {
                                    format!(" from {}", encrypted_group_info.sender_username)
                                } else {
                                    String::new()
                                };
                                
                                let total_size = encrypted_group_info.kem_output.len() + encrypted_group_info.ciphertext.len();
                                
                                debug!(
                                    "Received EncryptedGroupInfo ({} bytes) for external commit{}",
                                    total_size,
                                    sender_info
                                );

                                // Display who invited us and store their KeyPackage for future communication
                                if !encrypted_group_info.sender_username.is_empty() {
                                    if let Err(e) = display_sender
                                        .send(format!(
                                            "Received group invitation from {}",
                                            encrypted_group_info.sender_username
                                        ))
                                        .await
                                    {
                                        error!("Unable to send invitation notification to display: {e}");
                                    }
                                    
                                    // Store the sender's KeyPackage so we can message them back
                                    if !encrypted_group_info.sender_key_package.is_empty() {
                                        let sender_announcement = UserAnnouncement {
                                            username: encrypted_group_info.sender_username.clone(),
                                            tls_serialized_key_package: encrypted_group_info.sender_key_package.clone(),
                                        };
                                        
                                        Self::handle_network_user_announcement(
                                            &sender_announcement,
                                            crypto_actor.clone(),
                                            display_sender.clone(),
                                        )
                                        .await;
                                    }
                                }

                                // Send this to crypto actor for decryption and external commit creation
                                match crypto_actor
                                    .ask(CryptoIdentityMessage::ProcessEncryptedGroupInfo {
                                        encrypted_group_info: encrypted_group_info.clone(),
                                    })
                                    .await
                                {
                                    Ok(reply) => match reply {
                                        CryptoIdentityReply::MlsMessageOut(commit) => {
                                            // Convert to ProtoMlsMessageOut and send over network
                                            let mls_message_out_external_commit = if let Ok(msg) =
                                                commit.try_into()
                                            {
                                                msg
                                            } else {
                                                error!(
                                                    "Received invalid MlsMessageOut packet for external commit"
                                                );
                                                continue;
                                            };
                                            // Send the external commit message to the network
                                            if let Err(e) = network_manager
                                                .send_message(mls_message_out_external_commit)
                                                .await
                                            {
                                                error!(
                                                    "Failed to send external commit over network: {}",
                                                    e
                                                );
                                            };
                                            if let Err(e) = display_sender
                                                .send(format!(
                                                    "Decrypted EncryptedGroupInfo and created external commit successfully."
                                                ))
                                                .await
                                            {
                                                error!(
                                                    "Unable to send the decrypted msg to display: {e}"
                                                );
                                            };
                                        }
                                        CryptoIdentityReply::Failure(e) => {
                                            error!("Failed to process EncryptedGroupInfo: {e}");
                                        }
                                        _ => unreachable!("Some horrible thing happened."),
                                    },
                                    Err(e) => {
                                        if let Err(e) = display_sender.send(e.to_string()).await {
                                            error!("Unable to send the error msg to display: {e}");
                                        };
                                    }
                                }

                                if let Err(e) = display_sender
                                    .send(format!(
                                        "Received HPKE-encrypted GroupInfo for external commit join."
                                    ))
                                    .await
                                {
                                    error!("Unable to send encrypted group info notification: {e}");
                                }
                            }
                            _ => {
                                // All other messages (PublicMessage, PrivateMessage, Welcome, GroupInfo)
                                // go to the crypto actor as MlsMessageIn
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
                                        CryptoIdentityReply::MessageProcessed { result } => {
                                            // let's see what we got
                                            match result {
                                                ProcessedMessageResult::ApplicationMessage(m) => {
                                                    display_sender.send(format!("{m}")).await.expect(
                                                        "Unable to send the decrypted msg to display",
                                                    );
                                                }

                                                ProcessedMessageResult::StagedCommitMerged => {
                                                    if let Err(e) = display_sender
                                                        .send(format!(
                                                            "Staged commit merged successfully."
                                                        ))
                                                        .await
                                                    {
                                                        error!(
                                                            "Unable to send the list of users to display: {e}"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        CryptoIdentityReply::Failure(error) => {
                                            // downcast the error to error type
                                            match error.downcast_ref::<CryptoIdentityActorError>() {
                                                Some(e) => {
                                                    match e {
                                                        // silently ignore it because there could traffic for other groups
                                                        CryptoIdentityActorError::GroupNotFound(
                                                            _g,
                                                        ) => {}
                                                    }
                                                }
                                                None => {
                                                    error!(
                                                        "Unknown error type received: {}",
                                                        error
                                                    );
                                                }
                                            }
                                        }
                                        _ => {
                                            if let Err(e) = display_sender
                                                .send(format!("Unexpected packet type."))
                                                .await
                                            {
                                                error!(
                                                    "Unable to send the list of users to display: {e}"
                                                );
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        display_sender
                                            .send(e.to_string())
                                            .await
                                            .expect("Unable to send the error msg to display");
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
                let group = current_group.lock(); // parking_lot doesn't need unwrap
                let prompt = match &*group {
                    Some(g) => format!("\x1b[36m[{}]\x1b[0m {} > ", g, nick),
                    None => format!("{} > ", nick),
                };
                eprint!("{}", prompt);
            }
        })
    }

    async fn handle_network_user_announcement(
        user_announcement: &UserAnnouncement,
        crypto_actor: ActorRef<CryptoIdentityActor>,
        display_sender: tokio::sync::mpsc::Sender<String>,
    ) {
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
            Ok(reply) => match reply {
                CryptoIdentityReply::Success => {
                    if let Err(e) = display_sender
                        .send(format!(
                            "Processed UserAnnouncement from {}",
                            user_announcement.username
                        ))
                        .await
                    {
                        error!("Unable to send the decrypted msg to display: {e}");
                    };
                }
                CryptoIdentityReply::Failure(e) => {
                    error!("Failed to process new UserAnnouncement: {e}");
                }
                _ => unreachable!("Pack it up boys. We are done here."),
            },
            Err(e) => {
                if let Err(e) = display_sender.send(e.to_string()).await {
                    error!("Unable to send the error msg to display: {e}");
                };
            }
        }
    }
}
