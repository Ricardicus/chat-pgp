use ncurses::*;
use std::collections::HashMap;
use std::marker::PhantomData;

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{timeout, Duration};

use color_eyre::Result;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout, Position},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, List, ListItem, Paragraph},
    DefaultTerminal, Frame,
};

use serde::{Deserialize, Serialize};

pub struct WindowManager {
    windows: HashMap<usize, (WINDOW, WINDOW)>,
    keep_running: Arc<Mutex<bool>>,
    pipe: WindowPipe,
    ratatui_thread: Option<tokio::task::JoinHandle<()>>,
}

unsafe impl Send for WindowManager {}
unsafe impl Sync for WindowManager {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrintCommand {
    pub window: usize,
    pub message: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReadCommand {
    pub window: usize,
    pub prompt: String,
    pub upper_prompt: String,
    pub timeout: i32,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewWindowCommand {
    pub win_number: usize,
    pub start_y: i32,
    pub win_height: i32,
    pub win_width: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum WindowCommand {
    Println(PrintCommand),
    Print(PrintCommand),
    Read(ReadCommand),
    New(NewWindowCommand),
    Init(),
    Shutdown(),
}

pub struct WindowPipe {
    pub tx: Arc<Mutex<mpsc::Sender<WindowCommand>>>,
    pub rx: Arc<Mutex<mpsc::Receiver<WindowCommand>>>,
    pub tx_input: Arc<Mutex<mpsc::Sender<String>>>,
    pub rx_input: Arc<Mutex<mpsc::Receiver<String>>>,
    pub tx_chat_input: Arc<Mutex<mpsc::Sender<Option<String>>>>,
    pub rx_chat_input: Arc<Mutex<mpsc::Receiver<Option<String>>>>,
}

impl WindowPipe {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(50);
        let (tx_input, rx_input) = mpsc::channel(50);
        let (tx_chat_input, rx_chat_input) = mpsc::channel(50);
        Self {
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            tx_input: Arc::new(Mutex::new(tx_input)),
            rx_input: Arc::new(Mutex::new(rx_input)),
            tx_chat_input: Arc::new(Mutex::new(tx_chat_input)),
            rx_chat_input: Arc::new(Mutex::new(rx_chat_input)),
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            rx: self.rx.clone(),
            tx_input: self.tx_input.clone(),
            rx_input: self.rx_input.clone(),
            tx_chat_input: self.tx_chat_input.clone(),
            rx_chat_input: self.rx_chat_input.clone(),
        }
    }

    pub async fn read(&self) -> Result<WindowCommand, ()> {
        match self.rx.lock().await.recv().await {
            Some(msg) => Ok(msg),
            None => Err(()),
        }
    }

    pub async fn send(&self, cmd: WindowCommand) {
        let _ = self.tx.lock().await.send(cmd).await;
    }

    pub async fn get_input(
        &self,
        window: usize,
        prompt: &str,
        upper_prompt: &str,
        timeout: i32,
    ) -> Result<String, ()> {
        let cmd = ReadCommand {
            window,
            prompt: prompt.to_string(),
            upper_prompt: upper_prompt.to_string(),
            timeout,
        };
        let _ = self.tx.lock().await.send(WindowCommand::Read(cmd)).await;
        let mut rx;
        {
            rx = self.rx_input.lock().await;
        }

        match rx.recv().await {
            Some(msg) => Ok(msg),
            None => Err(()),
        }
    }

    pub async fn get_chat_input(&self) -> Result<Option<String>, ()> {
        let mut rx;
        {
            rx = self.rx_chat_input.lock().await;
        }
        match rx.recv().await {
            Some(Some(msg)) => Ok(Some(msg)),
            Some(None) => Ok(None),
            None => Err(()),
        }
    }
    pub async fn tx_input(&self, msg: String) {
        let _ = self.tx_input.lock().await.send(msg).await;
    }
    pub async fn tx_chat_input(&self, msg: Option<String>) {
        let _ = self.tx_chat_input.lock().await.send(msg).await;
    }
}

impl WindowManager {
    pub fn new() -> Self {
        WindowManager {
            windows: HashMap::new(),
            keep_running: Arc::new(Mutex::new(true)),
            pipe: WindowPipe::new(),
            ratatui_thread: None,
        }
    }

    pub async fn cleanup(&mut self) {}

    pub async fn init(&mut self) {
        if self.ratatui_thread.is_none() {
            let pipe = self.pipe.clone();
            self.ratatui_thread = Some(tokio::spawn(async move {
                match color_eyre::install() {
                    Err(_) => return,
                    _ => {}
                }
                let terminal = ratatui::init();
                let app_result = App::new().await.run(terminal, &pipe).await;
                ratatui::restore();
            }));
        }
    }

    pub async fn serve(&mut self, pipe: WindowPipe) {
        let mut keep_running;
        {
            keep_running = *self.keep_running.lock().await;
        }
        while keep_running {
            match pipe.read().await {
                Ok(command) => match command {
                    WindowCommand::Init() => {
                        self.init().await;
                    }
                    WindowCommand::Shutdown() => {
                        *self.keep_running.lock().await = false;
                    }
                    _ => {
                        self.pipe.send(command).await;
                    }
                },
                Err(()) => {}
            }
            {
                keep_running = *self.keep_running.lock().await;
            }
        }
        self.cleanup().await;
    }
}

/// App holds the state of the application
struct App {
    /// Current value of the input box
    input: Arc<Mutex<String>>,
    /// Position of cursor in the editor area.
    character_index: Arc<Mutex<usize>>,
    /// Current input mode
    input_mode: Arc<Mutex<InputMode>>,
    /// History of recorded messages
    messages_live: Arc<Mutex<HashMap<String, Vec<(usize, String)>>>>,

    should_run: Arc<Mutex<bool>>,
    notify: Arc<Semaphore>,
    command: Arc<Mutex<String>>,
    there_is_command: Arc<Mutex<bool>>,
}

#[derive(Clone, Copy)]
enum InputMode {
    Normal,
    Editing,
}

impl App {
    async fn new() -> Self {
        Self {
            input: Arc::new(Mutex::new(String::new())),
            input_mode: Arc::new(Mutex::new(InputMode::Normal)),
            command: Arc::new(Mutex::new(String::new())),
            character_index: Arc::new(Mutex::new(0)),
            messages_live: Arc::new(Mutex::new(HashMap::new())),
            should_run: Arc::new(Mutex::new(true)),
            notify: Arc::new(Semaphore::new(0)),
            there_is_command: Arc::new(Mutex::new(false)),
        }
    }

    fn clone(&self) -> Self {
        Self {
            input: self.input.clone(),
            input_mode: self.input_mode.clone(),
            character_index: self.character_index.clone(),
            messages_live: self.messages_live.clone(),
            should_run: self.should_run.clone(),
            notify: self.notify.clone(),
            command: self.command.clone(),
            there_is_command: self.there_is_command.clone(),
        }
    }

    async fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.character_index.lock().await.saturating_sub(1);
        *self.character_index.lock().await = self.clamp_cursor(cursor_moved_left).await;
    }

    async fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.character_index.lock().await.saturating_add(1);
        *self.character_index.lock().await = self.clamp_cursor(cursor_moved_right).await;
    }

    async fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index().await;
        self.input.lock().await.insert(index, new_char);
        self.move_cursor_right().await;
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    async fn byte_index(&self) -> usize {
        let mut s = self.input.lock().await;
        let len = s.len();
        let char_index;
        {
            char_index = *self.character_index.lock().await;
        }
        s.char_indices()
            .map(|(i, _)| i)
            .nth(char_index)
            .unwrap_or(len)
    }

    async fn delete_char(&mut self) {
        let is_not_cursor_leftmost = *self.character_index.lock().await != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = *self.character_index.lock().await;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let mut input;
            {
                input = self.input.lock().await.clone();
            }
            let before_char_to_delete = input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            *self.input.lock().await = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left().await;
        }
    }

    async fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.lock().await.chars().count())
    }

    async fn reset_cursor(&mut self) {
        *self.character_index.lock().await = 0;
    }

    async fn submit_message(&mut self) {
        {
            let s = self.input.lock().await.clone();
            *self.command.lock().await = s;
            self.input.lock().await.clear();
            self.reset_cursor().await;
            self.set_input_mode(InputMode::Normal).await;
            *self.there_is_command.lock().await = true;
        }
    }
    async fn await_submit(&self) {
        let mut keep_waiting;
        {
            keep_waiting = !*self.there_is_command.lock().await;
        }
        while keep_waiting && self.should_run().await {
            tokio::time::sleep(Duration::from_millis(100)).await;
            {
                keep_waiting = !*self.there_is_command.lock().await;
            }
        }
    }

    async fn get_input_mode(&self) -> InputMode {
        let im = self.input_mode.lock().await;
        return *im;
    }
    async fn set_input_mode(&self, input_mode: InputMode) {
        *self.input_mode.lock().await = input_mode;
    }
    async fn should_run(&self) -> bool {
        return *self.should_run.lock().await;
    }
    async fn set_terminate(&mut self) {
        *self.should_run.lock().await = false;
    }
    async fn get_character_index(&self) -> usize {
        return *self.character_index.lock().await;
    }
    async fn get_input(&self) -> String {
        let s = self.input.lock().await;
        s.to_string()
    }
    async fn get_submitted(&self) -> String {
        let s = self.command.lock().await;
        s.to_string()
    }
    async fn write_new_message(&mut self, window: usize, message: String) {
        let mut messages_live;
        {
            messages_live = self.messages_live.clone();
        }
        let mut hm = messages_live.lock().await;
        let entry = (window, message);
        if let Some(v) = hm.get_mut("messages") {
            v.push(entry);
        } else {
            let mut v = Vec::new();
            v.push(entry);
            hm.insert("messages".to_string(), v);
        }
    }
    async fn set_last_message(&mut self, window: usize, message: String) {
        let mut messages_live;
        {
            messages_live = self.messages_live.clone();
        }
        let mut hm = messages_live.lock().await;
        if let Some(v) = hm.get_mut("messages") {
            if let Some(last) = v.last_mut() {
                // Append the string `s1` to the String part of the last element
                last.1.push_str(&message);
            }
        } else {
            let mut v = Vec::new();
            v.push((window, message));
            hm.insert("messages".to_string(), v);
        }
    }

    async fn run(&mut self, mut terminal: DefaultTerminal, pipe: &WindowPipe) {
        let pipe = pipe.clone();
        let mut app = self.clone();
        let mut messages_live;
        {
            messages_live = self.messages_live.clone();
        }
        let h2 = tokio::spawn(async move {
            while app.should_run().await {
                let len = messages_live.lock().await.len();

                let timeout_duration = Duration::from_secs(1);
                match timeout(timeout_duration, pipe.read()).await {
                    Ok(Ok(command)) => match command {
                        WindowCommand::Print(cmd) => {
                            app.set_last_message(cmd.window, cmd.message).await;
                        }
                        WindowCommand::Println(cmd) => {
                            app.write_new_message(cmd.window, cmd.message).await;
                        }
                        WindowCommand::Read(cmd) => {
                            app.write_new_message(cmd.window, cmd.prompt).await;
                            app.await_submit().await;
                            let s = app.get_submitted().await;
                            pipe.tx_input(s.clone()).await;
                            app.set_last_message(cmd.window, s).await;
                        }
                        _ => {}
                    },
                    Ok(Err(_)) => {
                        println!("got an error");
                    }
                    Err(_) => {}
                };
            }
        });
        let mut messages_live;
        {
            messages_live = self.messages_live.clone();
        }
        let mut app = self.clone();
        let h1 = tokio::spawn(async move {
            while app.should_run().await {
                let messages;
                {
                    messages = messages_live.lock().await;
                }
                let len = messages.len();
                let input = app.get_input().await;
                let character_index = app.get_character_index().await;
                let input_mode = app.get_input_mode().await;
                let mut v = Vec::<(usize, String)>::new();
                if let Some(msgs) = messages.get("messages") {
                    v = msgs.to_vec();
                }
                let _ =
                    terminal.draw(|frame| App::draw(frame, v, input_mode, input, character_index));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let mut app = self.clone();
        let h3 = tokio::spawn(async move {
            while app.should_run().await {
                if let Event::Key(key) = event::read().unwrap() {
                    match app.get_input_mode().await {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('e') => {
                                app.set_input_mode(InputMode::Editing).await;
                            }
                            KeyCode::Char('q') => {
                                app.set_terminate().await;
                                continue;
                            }
                            _ => {}
                        },
                        InputMode::Editing if key.kind == KeyEventKind::Press => match key.code {
                            KeyCode::Enter => app.submit_message().await,
                            KeyCode::Char(to_insert) => app.enter_char(to_insert).await,
                            KeyCode::Backspace => app.delete_char().await,
                            KeyCode::Left => app.move_cursor_left().await,
                            KeyCode::Right => app.move_cursor_right().await,
                            KeyCode::Esc => app.set_input_mode(InputMode::Normal).await,
                            _ => {}
                        },
                        InputMode::Editing => {}
                    }
                }
            }
        });

        h1.await.unwrap();
        h2.await.unwrap();
        h3.await.unwrap();
    }

    fn draw(
        frame: &mut Frame,
        messages: Vec<(usize, String)>,
        input_mode: InputMode,
        input: String,
        character_index: usize,
    ) {
        let vertical = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ]);
        let [help_area, input_area, messages_area] = vertical.areas(frame.area());
        if messages.len() > 0 {
        } else {
        }
        let (msg, style) = match input_mode {
            InputMode::Normal => (
                vec![
                    "Press ".into(),
                    "q".bold(),
                    " to exit, ".into(),
                    "e".bold(),
                    " to start editing.".bold(),
                ],
                Style::default().add_modifier(Modifier::RAPID_BLINK),
            ),
            InputMode::Editing => (
                vec![
                    "Press ".into(),
                    "Esc".bold(),
                    " to stop editing, ".into(),
                    "Enter".bold(),
                    " to record the message".into(),
                ],
                Style::default(),
            ),
        };
        let text = Text::from(Line::from(msg)).patch_style(style);
        let help_message = Paragraph::new(text);
        frame.render_widget(help_message, help_area);

        let input = Paragraph::new(input.as_str())
            .style(match input_mode {
                InputMode::Normal => Style::default(),
                InputMode::Editing => Style::default().fg(Color::Yellow),
            })
            .block(Block::bordered().title("Input"));
        frame.render_widget(input, input_area);
        match input_mode {
            // Hide the cursor. `Frame` does this by default, so we don't need to do anything here
            InputMode::Normal => {}

            // Make the cursor visible and ask ratatui to put it at the specified coordinates after
            // rendering
            #[allow(clippy::cast_possible_truncation)]
            InputMode::Editing => frame.set_cursor_position(Position::new(
                // Draw the cursor at the current position in the input field.
                // This position is can be controlled via the left and right arrow key
                input_area.x + character_index as u16 + 1,
                // Move one line down, from the border to the input line
                input_area.y + 1,
            )),
        }

        let messages: Vec<ListItem> = messages
            .iter()
            .map(|(i, m)| {
                let content = Line::from(Span::raw(format!("{m}")));
                ListItem::new(content)
            })
            .collect();
        let messages = List::new(messages).block(Block::bordered().title("Messages"));
        frame.render_widget(messages, messages_area);
    }
}
