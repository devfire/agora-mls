use tracing::debug;

use crate::command::Command;

pub fn handle_command(command: Command) {
    match command {
        Command::Join { channel, password } => {
            debug!(
                "Joining channel: {}, with password: {:?}",
                channel, password
            );

            
        }
        Command::Leave { channel } => todo!(),
        Command::Msg { user, message } => todo!(),
        Command::Nick { nickname } => todo!(),
        Command::Users => todo!(),
        Command::Channels => todo!(),
        Command::Quit => todo!(),
    }
}
