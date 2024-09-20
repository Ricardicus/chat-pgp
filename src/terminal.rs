use ncurses::*;
use std::collections::HashMap;
use std::marker::PhantomData;

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify, OnceCell, Semaphore};
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
    pipe: WindowPipe<WindowCommand>,
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

#[derive(Clone)]
pub struct WindowPipe<T> {
    pub tx: Arc<Mutex<mpsc::Sender<T>>>,
    pub rx: Arc<Mutex<mpsc::Receiver<T>>>,
}

impl<T> WindowPipe<T> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(50);
        Self {
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            rx: self.rx.clone(),
        }
    }

    pub async fn read(&self) -> Result<T, ()> {
        match self.rx.lock().await.recv().await {
            Some(msg) => Ok(msg),
            None => Err(()),
        }
    }

    pub async fn send(&self, cmd: T) {
        let _ = self.tx.lock().await.send(cmd).await;
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

    pub async fn init(&mut self, tx: mpsc::Sender<Option<String>>) {
        if self.ratatui_thread.is_none() {
            let pipe = self.pipe.clone();
            self.ratatui_thread = Some(tokio::spawn(async move {
                match color_eyre::install() {
                    Err(_) => return,
                    _ => {}
                }
                let terminal = ratatui::init();
                let _ = App::new(tx.clone()).await.run(terminal, &pipe).await;
                ratatui::restore();
            }));
        }
    }

    pub async fn serve(
        &mut self,
        pipe: WindowPipe<WindowCommand>,
        tx_terminal: mpsc::Sender<Option<String>>,
    ) {
        let mut keep_running;
        {
            keep_running = *self.keep_running.lock().await;
        }
        while keep_running {
            match pipe.read().await {
                Ok(command) => match command {
                    WindowCommand::Init() => {
                        self.init(tx_terminal.clone()).await;
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

#[derive(Clone)]
struct AppState {
    pub input: String,
    pub input_mode: InputMode,
    pub character_index: usize,
    pub messages: Vec<String>,
}

/// App holds the state of the application
struct App {
    state: Arc<Mutex<AppState>>,
    should_run: Arc<Mutex<bool>>,
    tx: mpsc::Sender<Option<String>>,
}

#[derive(Clone, Copy)]
enum InputMode {
    Normal,
    Editing,
}

impl App {
    async fn new(tx: mpsc::Sender<Option<String>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState {
                input: String::new(),
                input_mode: InputMode::Normal,
                character_index: 0,
                messages: Vec::new(),
            })),
            should_run: Arc::new(Mutex::new(true)),
            tx: tx,
        }
    }

    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            should_run: self.should_run.clone(),
            tx: self.tx.clone(),
        }
    }

    async fn move_cursor_left(&mut self, len: usize) {
        let mut state = self.state.lock().await;
        let cursor_moved_left = state.character_index.saturating_sub(1);
        state.character_index = self.clamp_cursor(cursor_moved_left, len).await;
    }

    async fn move_cursor_right(&mut self, len: usize) {
        let mut state = self.state.lock().await;
        let cursor_moved_right = state.character_index.saturating_add(1);
        state.character_index = self.clamp_cursor(cursor_moved_right, len).await;
    }

    async fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index().await;
        {
            let mut state = self.state.lock().await;
            state.input.insert(index, new_char);
        }
        self.move_cursor_right(index + 1).await;
    }

    async fn byte_index(&self) -> usize {
        let state = self.state.lock().await;
        let mut s = &state.input;
        let len = s.len();
        let char_index;
        {
            char_index = state.character_index;
        }
        s.char_indices()
            .map(|(i, _)| i)
            .nth(char_index)
            .unwrap_or(len)
    }

    async fn delete_char(&mut self) {
        let mut len = None;
        {
            let mut state = self.state.lock().await;
            let is_not_cursor_leftmost;
            {
                is_not_cursor_leftmost = state.character_index != 0
            };
            if is_not_cursor_leftmost {
                // Method "remove" is not used on the saved text for deleting the selected char.
                // Reason: Using remove on String works on bytes instead of the chars.
                // Using remove would require special care because of char boundaries.

                let current_index;
                {
                    current_index = state.character_index;
                }
                let from_left_to_current_index = current_index - 1;

                // Getting all characters before the selected character.
                let mut input;
                {
                    input = state.input.clone();
                }
                len = Some(input.len());
                let before_char_to_delete = input.chars().take(from_left_to_current_index);
                // Getting all characters after selected character.
                let after_char_to_delete = input.chars().skip(current_index);

                // Put all characters together except the selected one.
                // By leaving the selected one out, it is forgotten and therefore deleted.
                {
                    state.input = before_char_to_delete.chain(after_char_to_delete).collect();
                }
            }
        }
        if len.is_some() {
            self.move_cursor_left(len.unwrap()).await;
        }
    }
    //self.input.lock().await.chars().count()
    async fn clamp_cursor(&self, new_cursor_pos: usize, len: usize) -> usize {
        new_cursor_pos.clamp(0, len)
    }

    async fn reset_cursor(&mut self) {
        let mut state = self.state.lock().await;
        state.character_index = 0;
    }

    async fn submit_message(&mut self) {
        let input;
        {
            let mut state = self.state.lock().await;
            input = state.input.clone();
            state.input = String::new();
        }
        self.reset_cursor().await;
        self.set_input_mode(InputMode::Normal).await;
        self.tx.send(Some(input)).await;
    }

    async fn get_input_mode(&self) -> InputMode {
        let state = self.state.lock().await;
        return state.input_mode;
    }
    async fn get_state(&self) -> AppState {
        let state = self.state.lock().await;
        state.clone()
    }
    async fn set_input_mode(&self, input_mode: InputMode) {
        let mut state = self.state.lock().await;
        state.input_mode = input_mode;
    }
    async fn should_run(&self) -> bool {
        return *self.should_run.lock().await;
    }
    async fn set_terminate(&mut self) {
        *self.should_run.lock().await = false;
    }
    async fn get_character_index(&self) -> usize {
        let state = self.state.lock().await;
        state.character_index
    }
    async fn get_input(&self) -> String {
        let state = self.state.lock().await;
        state.input.clone()
    }
    async fn get_input_len(&self) -> usize {
        let state = self.state.lock().await;
        state.input.chars().count()
    }
    async fn write_new_message(&mut self, window: usize, message: String) {
        let mut state = self.state.lock().await;
        state.messages.push(message);
    }
    async fn set_last_message(&mut self, window: usize, message: String) {
        let mut state = self.state.lock().await;
        if state.messages.len() > 0 {
            if let Some(last) = state.messages.last_mut() {
                // Append the string `s1` to the String part of the last element
                last.push_str(&message);
            }
        } else {
            state.messages.push(message);
        }
    }

    async fn run(&mut self, mut terminal: DefaultTerminal, pipe: &WindowPipe<WindowCommand>) {
        let pipe = pipe.clone();
        let mut app = self.clone();

        // First task to initialize the global value
        let initializer = tokio::spawn(async {
            initialize_global_values().await;
        });

        // Wait for the initializer to complete
        initializer.await.unwrap();

        let h2 = tokio::spawn(async move {
            let mut should_run;
            {
                should_run = app.should_run().await;
            }
            while should_run {
                let timeout_duration = Duration::from_millis(100);
                match timeout(timeout_duration, pipe.read()).await {
                    Ok(Ok(command)) => {
                        match command {
                            WindowCommand::Print(cmd) => {
                                app.set_last_message(cmd.window, cmd.message).await;
                            }
                            WindowCommand::Println(cmd) => {
                                app.write_new_message(cmd.window, cmd.message).await;
                            }
                            /*WindowCommand::Read(cmd) => {
                                app.write_new_message(cmd.window, cmd.prompt).await;
                                app.await_submit().await;
                                let s = app.get_submitted().await;
                                //send_terminal_input(s.clone()).await;
                                //pipe.tx_input(s.clone()).await;
                                app.set_last_message(cmd.window, s).await;
                            }*/
                            _ => {}
                        };
                        // let state = app.get_state().await;
                        // send_app_state(state).await;
                    }
                    Ok(Err(_)) => {
                        println!("got an error");
                    }
                    Err(_) => {}
                };
                {
                    should_run = app.should_run().await;
                }

                send_app_state(app.get_state().await).await;
            }
        });
        let mut app = self.clone();
        let h1 = tokio::spawn(async move {
            let mut should_run;
            {
                should_run = app.should_run().await;
            }
            while should_run {
                let state = read_app_state().await.unwrap();
                let messages = state.messages;
                let input = state.input;
                let input_mode = state.input_mode;
                let character_index = state.character_index;
                let _ = terminal
                    .draw(|frame| App::draw(frame, messages, input_mode, input, character_index));
                {
                    should_run = app.should_run().await;
                }
            }
        });

        let app = self.clone();
        tokio::spawn(async move {
            let mut should_run;
            {
                should_run = app.should_run().await;
            }
            let update_interval_millis = 100;
            while should_run {
                send_app_state(app.get_state().await).await;
                tokio::time::sleep(Duration::from_millis(update_interval_millis)).await;
                {
                    should_run = app.should_run().await;
                }
            }
        });

        let mut app = self.clone();
        let tx = self.tx.clone();
        let h3 = tokio::spawn(async move {
            let mut should_run;
            {
                should_run = app.should_run().await;
            }
            while should_run {
                if let Event::Key(key) = event::read().unwrap() {
                    let input_mode;
                    {
                        input_mode = app.get_input_mode().await;
                    }
                    match input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('e') => {
                                app.set_input_mode(InputMode::Editing).await;
                            }
                            KeyCode::Char('q') => {
                                app.set_terminate().await;
                                let _ = tx.send(None).await;
                            }
                            _ => {}
                        },
                        InputMode::Editing if key.kind == KeyEventKind::Press => {
                            let len = app.get_input_len().await;
                            match key.code {
                                KeyCode::Enter => app.submit_message().await,
                                KeyCode::Char(to_insert) => app.enter_char(to_insert).await,
                                KeyCode::Backspace => app.delete_char().await,
                                KeyCode::Left => app.move_cursor_left(len).await,
                                KeyCode::Right => app.move_cursor_right(len).await,
                                KeyCode::Esc => app.set_input_mode(InputMode::Normal).await,
                                _ => {}
                            }
                        }
                        InputMode::Editing => {}
                    }
                }
                {
                    //send_app_state(app.get_state().await).await;
                }
                {
                    should_run = app.should_run().await;
                }
            }
        });

        h1.await.unwrap();
        h2.await.unwrap();
        h3.await.unwrap();
    }

    fn draw(
        frame: &mut Frame,
        messages: Vec<String>,
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
                    " to write".into(),
                ],
                Style::default().add_modifier(Modifier::RAPID_BLINK),
            ),
            InputMode::Editing => (
                vec![
                    "Press ".into(),
                    "Esc".bold(),
                    " to stop editing, ".into(),
                    "Enter".bold(),
                    " to submit the message".into(),
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
            .map(|m| {
                let content = Line::from(Span::raw(format!("{m}")));
                ListItem::new(content)
            })
            .collect();
        let messages = List::new(messages).block(Block::bordered().title("Messages"));
        frame.render_widget(messages, messages_area);
    }
}

static STATE: OnceCell<Arc<WindowPipe<AppState>>> = OnceCell::const_new();

async fn initialize_global_values() {
    // Directly initialize the GLOBAL_VALUE using `init`
    let _ = STATE.set(Arc::new(WindowPipe::<AppState>::new()));
}

pub async fn read_app_state() -> Result<AppState, ()> {
    match STATE.get().unwrap().read().await {
        Ok(cmd) => Ok(cmd),
        Err(_) => Err(()),
    }
}

async fn send_app_state(state: AppState) {
    let _ = STATE.get().unwrap().send(state).await;
}
