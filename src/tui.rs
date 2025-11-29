use anyhow::Result;
use parking_lot::Mutex;
use ratatui::{
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::{io, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tui_textarea::TextArea;

use crate::command::Command;

pub struct Tui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Tui {
    pub fn new() -> Result<Self> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn enter(&mut self) -> Result<()> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        self.terminal.clear()?;
        Ok(())
    }

    pub fn exit(&mut self) -> Result<()> {
        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    pub async fn run(
        &mut self,
        nick: String,
        current_group: Arc<Mutex<Option<String>>>,
        command_sender: mpsc::Sender<Command>,
        message_sender: mpsc::Sender<String>,
        mut display_receiver: mpsc::Receiver<String>,
    ) -> Result<()> {
        let mut textarea = TextArea::default();
        textarea.set_cursor_line_style(Style::default());
        textarea.set_placeholder_text("Type a message or command...");

        // Use a block for the textarea to give it a border
        textarea.set_block(Block::default().borders(Borders::ALL).title("Input"));

        let mut messages: Vec<String> = Vec::new();
        let mut auto_scroll = true;
        let mut input_history: Vec<String> = Vec::new();
        let mut history_index = 0;

        loop {
            // Determine the current prompt based on group
            let prompt = {
                let group = current_group.lock();
                if let Some(ref g) = *group {
                    format!("[{}] {} > ", g, nick)
                } else {
                    format!("{} > ", nick)
                }
            };

            textarea.set_block(Block::default().borders(Borders::ALL).title(prompt));

            // Calculate suggestion
            let mut suggestion: Option<String> = None;
            let input = textarea.lines()[0].clone();
            if input.starts_with('/') {
                let current_cmd = &input[1..];
                let commands = crate::command::CommandCompleter::get_commands();

                // Find first matching command
                if let Some(match_cmd) = commands.iter().find(|cmd| cmd.starts_with(current_cmd)) {
                    if match_cmd.len() > current_cmd.len() {
                        suggestion = Some(match_cmd[current_cmd.len()..].to_string());
                    }
                }
            }

            self.terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(1),    // Messages area
                        Constraint::Length(3), // Input area
                    ])
                    .split(f.area());

                // Render Messages
                let messages_widget = List::new(
                    messages
                        .iter()
                        .map(|m| ListItem::new(Text::from(m.as_str())))
                        .collect::<Vec<_>>(),
                )
                .block(Block::default().borders(Borders::ALL).title("Messages"))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD));

                let mut state = ratatui::widgets::ListState::default();
                if !messages.is_empty() && auto_scroll {
                    state.select(Some(messages.len() - 1));
                }

                f.render_stateful_widget(messages_widget, chunks[0], &mut state);

                // Render Input
                f.render_widget(&textarea, chunks[1]);

                // Render Ghost Text Suggestion
                if let Some(ref sugg) = suggestion {
                    // Calculate position (assuming single line and no horizontal scrolling for simplicity)
                    // We need to account for the border (1 char) and the prompt length if it was part of the textarea content,
                    // but here the prompt is in the title, so we just care about the text content.
                    // Wait, textarea content starts at x+1, y+1.

                    use unicode_width::UnicodeWidthStr;
                    let input_width = input.width();

                    // Only show if it fits
                    if (input_width as u16) < chunks[1].width - 2 {
                        let ghost_x = chunks[1].x + 1 + input_width as u16;
                        let ghost_y = chunks[1].y + 1;

                        let ghost_text = Paragraph::new(sugg.clone())
                            .style(Style::default().fg(Color::DarkGray));

                        f.render_widget(
                            ghost_text,
                            Rect::new(
                                ghost_x,
                                ghost_y,
                                chunks[1].width - 2 - input_width as u16,
                                1,
                            ),
                        );
                    }
                }
            })?;

            // Handle events
            if event::poll(Duration::from_millis(10))? {
                match event::read()? {
                    Event::Key(key) => match key.code {
                        KeyCode::Up => {
                            if !input_history.is_empty() {
                                if history_index > 0 {
                                    history_index -= 1;
                                    textarea.delete_line_by_head();
                                    textarea.insert_str(&input_history[history_index]);
                                }
                            }
                        }
                        KeyCode::Down => {
                            if !input_history.is_empty() {
                                if history_index < input_history.len() {
                                    history_index += 1;
                                    textarea.delete_line_by_head();
                                    if history_index < input_history.len() {
                                        textarea.insert_str(&input_history[history_index]);
                                    }
                                }
                            }
                        }
                        KeyCode::Tab | KeyCode::Right => {
                            // Accept suggestion if available (Right arrow or Tab)
                            // Note: Tab also does autocomplete logic which is slightly different (finds match vs uses pre-calc suggestion)
                            // But they should converge.

                            if let Some(ref sugg) = suggestion {
                                textarea.insert_str(sugg);
                            } else if key.code == KeyCode::Tab {
                                // Fallback to the previous Tab logic if no simple suffix suggestion (e.g. if we want to cycle?)
                                // For now, the suggestion logic covers the basic autocomplete case.
                                // But let's keep the explicit Tab logic as a backup or for when we don't have a ghost text but have a match?
                                // Actually, the ghost text logic is: "starts_with" -> "suffix".
                                // The Tab logic was: "starts_with" -> "replace line with match".
                                // They are compatible.

                                // If no suggestion was found (e.g. exact match already?), do nothing.
                            }
                        }
                        KeyCode::Enter => {
                            let input = textarea.lines()[0].clone();
                            if !input.is_empty() {
                                textarea.delete_line_by_head();

                                // Add to history
                                if input_history.last() != Some(&input) {
                                    input_history.push(input.clone());
                                }
                                history_index = input_history.len();

                                if input.starts_with('/') {
                                    match Command::parse_command(&input) {
                                        Ok(c) => {
                                            if let Command::Quit = c {
                                                return Ok(());
                                            }
                                            if let Err(_) = command_sender.send(c).await {
                                                return Ok(());
                                            }
                                        }
                                        Err(_) => {
                                            messages.push(
                                                "Invalid command. Type /help for help.".to_string(),
                                            );
                                        }
                                    }
                                } else {
                                    if let Err(_) = message_sender.send(input).await {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                        _ => {
                            textarea.input(key);
                        }
                    },
                    _ => {}
                }
            }

            while let Ok(msg) = display_receiver.try_recv() {
                let clean_msg = msg.replace("\r\x1b[K", "");
                messages.push(clean_msg);
                auto_scroll = true;
            }
        }
    }
}
