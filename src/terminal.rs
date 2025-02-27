use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, OnceCell};
use tokio::time::{timeout, Duration};

use crate::session::crypto::{Cryptical, CrypticalID};
use crate::util::{get_current_datetime, short_fingerprint};

use color_eyre::Result;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Flex, Layout, Position, Rect},
    prelude::Margin,
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    DefaultTerminal, Frame,
};

use serde::{Deserialize, Serialize};

pub struct WindowManager {
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
    pub style: TextStyle,
    pub color: TextColor,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatClosedCommand {
    pub message: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrintChatCommand {
    pub chatid: String,
    pub message: String,
    pub date_time: String,
}
impl PrintChatCommand {
    fn convert_to_printcmd_vec(&self) -> Vec<PrintCommand> {
        let mut v = Vec::new();
        let msg = PrintCommand {
            window: 1,
            message: format!("{} ", self.date_time),
            style: TextStyle::Bold,
            color: TextColor::DarkGray,
        };
        v.push(msg);
        let msg = PrintCommand {
            window: 1,
            message: format!("{}: ", self.chatid),
            style: TextStyle::Bold,
            color: TextColor::Gray,
        };
        v.push(msg);
        let msg = PrintCommand {
            window: 1,
            message: format!("{}", self.message),
            style: TextStyle::Normal,
            color: TextColor::White,
        };
        v.push(msg);
        v
    }
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
pub struct SetChatMessagesCommand {
    pub chat_messages: Vec<Vec<PrintChatCommand>>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetAppStateCommand {
    pub state: AppCurrentState,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestCommand {
    pub message: String,
    pub style: TextStyle,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum WindowCommand {
    Println(PrintCommand),
    Print(PrintCommand),
    PrintChat(PrintChatCommand),
    Read(ReadCommand),
    New(NewWindowCommand),
    ChatClosed(ChatClosedCommand),
    SetChatMessages(SetChatMessagesCommand),
    SetAppState(SetAppStateCommand),
    Request(RequestCommand),
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
            keep_running: Arc::new(Mutex::new(true)),
            pipe: WindowPipe::new(),
            ratatui_thread: None,
        }
    }

    pub async fn cleanup(&mut self) {}

    pub async fn init(&mut self, tx: mpsc::Sender<Option<WindowCommand>>) {
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
        tx_terminal: mpsc::Sender<Option<WindowCommand>>,
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AppCurrentState {
    Commands,
    Chat,
    Request,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TextStyle {
    Italic,
    Bold,
    Normal,
    Blinking,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TextColor {
    White,
    Green,
    Blue,
    Red,
    Gray,
    DarkGray,
    Yellow,
    Magenta,
    Black,
    LightRed,
    LightGreen,
    LightYellow,
    LightBlue,
    LightMagenta,
    LightCyan,
}

#[derive(Clone)]
struct AppState {
    pub input: String,
    pub input_mode: InputMode,
    pub request_text: String,
    pub character_index: usize,
    pub character_indexy: usize,
    pub messages: Vec<Vec<PrintCommand>>,
    pub chat_messages: Vec<Vec<PrintCommand>>,
    pub chatid: String,
    pub vertical_position_chat: usize,
    pub vertical_position_commands: usize,
    pub horizontal_position_chat: usize,
    pub horizontal_position_commands: usize,
    pub scrollstate_chat: ScrollbarState,
    pub scrollstate_commands: ScrollbarState,
    pub app_current_state: AppCurrentState,
}

/// App holds the state of the application
struct App {
    state: Arc<Mutex<AppState>>,
    should_run: Arc<Mutex<bool>>,
    tx: mpsc::Sender<Option<WindowCommand>>,
}

#[derive(Clone, Copy)]
enum InputMode {
    Normal,
    Editing,
}

impl App {
    async fn new(tx: mpsc::Sender<Option<WindowCommand>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState {
                input: String::new(),
                input_mode: InputMode::Normal,
                request_text: String::new(),
                character_index: 0,
                character_indexy: 0,
                messages: Vec::new(),
                chat_messages: Vec::new(),
                chatid: "Nobody".to_string(),
                vertical_position_chat: 0,
                vertical_position_commands: 0,
                horizontal_position_chat: 0,
                horizontal_position_commands: 0,
                scrollstate_chat: ScrollbarState::default(),
                scrollstate_commands: ScrollbarState::default(),
                app_current_state: AppCurrentState::Commands,
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

    async fn clear_chat(&mut self) {
        let mut state = self.state.lock().await;
        state.chat_messages.clear();
    }

    async fn is_in_chat_mode(&self) -> bool {
        self.state.lock().await.app_current_state == AppCurrentState::Chat
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

    async fn move_cursor_up(&mut self) {
        let len = self.get_input_len().await;
        let mut state = self.state.lock().await;
        let cursor_moved_y = state.character_indexy.saturating_sub(1);
        state.character_indexy = self.clamp_cursor(cursor_moved_y, len).await;
    }

    async fn move_cursor_down(&mut self) {
        let len = self.get_input_len().await;
        let mut state = self.state.lock().await;
        let cursor_moved_y = state.character_indexy.saturating_add(1);
        state.character_indexy = self.clamp_cursor(cursor_moved_y, len).await;
    }

    async fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index().await;
        {
            let mut state = self.state.lock().await;
            let indexy = state.character_indexy;
            if indexy == 0 {
                state.input.insert(index, new_char);
            } else {
                let mut lines: Vec<String> = state.input.lines().map(String::from).collect();
                while lines.len() <= indexy {
                    lines.push("".into());
                }
                if let Some(line) = lines.get_mut(indexy) {
                    // Insert the character at the given index in the specified line
                    while line.len() <= index {
                        line.push(' ');
                    }
                    line.insert(index, new_char);
                }
                // Reconstruct state.input
                state.input = lines.join("\n");
            }
        }
        if new_char == '\n' {
            self.move_cursor_down().await;
            self.reset_cursor_horizontal().await;
        } else {
            self.move_cursor_right(index + 1).await;
        }
    }

    async fn byte_index(&self) -> usize {
        let state = self.state.lock().await;
        let s = &state.input;
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
            let indexy = state.character_indexy;
            let index = state.character_index;
            if is_not_cursor_leftmost {
                let mut lines: Vec<String> = state.input.lines().map(String::from).collect();
                while lines.len() <= indexy {
                    lines.push("".into());
                }
                if let Some(line) = lines.get_mut(indexy) {
                    // Insert the character at the given index in the specified line
                    while line.len() < index {
                        line.push(' ');
                    }
                }
                // Reconstruct state.input
                state.input = lines.join("\n");

                let mut lines: Vec<String> = state.input.lines().map(String::from).collect();
                while lines.len() <= indexy {
                    lines.push("".into());
                }
                if let Some(line) = lines.get_mut(indexy) {
                    let current_index;
                    {
                        current_index = state.character_index;
                    }
                    let from_left_to_current_index = current_index - 1;
                    let input: String = line.clone();
                    len = Some(input.len());
                    let before_char_to_delete = input.chars().take(from_left_to_current_index);
                    let after_char_to_delete = input.chars().skip(current_index);
                    line.clear();
                    line.push_str(
                        &before_char_to_delete
                            .chain(after_char_to_delete)
                            .collect::<String>(),
                    );
                }
                // Reconstruct state.input
                state.input = lines.join("\n");
            } else {
                let mut lines: Vec<String> = state.input.lines().map(String::from).collect();
                while lines.len() <= indexy {
                    lines.push("".into());
                }
                if lines[indexy].len() == 0 {
                    lines.remove(indexy);
                }
                // Reconstruct state.input
                state.input = lines.join("\n");
            }
        }
        if len.is_some() {
            self.move_cursor_left(len.unwrap()).await;
        }
    }

    async fn clamp_cursor(&self, new_cursor_pos: usize, len: usize) -> usize {
        new_cursor_pos.clamp(0, len)
    }

    async fn reset_cursor_horizontal(&mut self) {
        let mut state = self.state.lock().await;
        state.character_index = 0;
    }

    async fn reset_cursor_vertical(&mut self) {
        let mut state = self.state.lock().await;
        state.character_indexy = 0;
    }

    async fn submit_message(&mut self) {
        let input;
        {
            let mut state = self.state.lock().await;
            input = state.input.clone();
            state.input = String::new();
        }
        self.reset_cursor_horizontal().await;
        self.reset_cursor_vertical().await;
        self.set_input_mode(InputMode::Normal).await;
        let _ = self
            .tx
            .send(Some(WindowCommand::Println(PrintCommand {
                window: 1,
                message: input,
                style: TextStyle::Normal,
                color: TextColor::White,
            })))
            .await;
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
    async fn move_vertical_scroll_down(&mut self) {
        let mut state = self.state.lock().await;
        match state.app_current_state {
            AppCurrentState::Commands => {
                state.vertical_position_commands =
                    state.vertical_position_commands.saturating_add(1);
                state.scrollstate_commands = state
                    .scrollstate_commands
                    .position(state.vertical_position_chat);
            }
            AppCurrentState::Chat => {
                state.vertical_position_chat = state.vertical_position_chat.saturating_add(1);
                state.scrollstate_chat = state
                    .scrollstate_chat
                    .position(state.vertical_position_chat);
            }
            AppCurrentState::Request => {
                state.character_indexy = state.character_indexy.saturating_add(1);
            }
        }
    }

    async fn move_vertical_scroll_up(&mut self) {
        let mut state = self.state.lock().await;

        match state.app_current_state {
            AppCurrentState::Commands => {
                state.vertical_position_commands =
                    state.vertical_position_commands.saturating_sub(1);
                state.scrollstate_commands = state
                    .scrollstate_commands
                    .position(state.vertical_position_chat);
            }
            AppCurrentState::Chat => {
                state.vertical_position_chat = state.vertical_position_chat.saturating_sub(1);
                state.scrollstate_chat = state
                    .scrollstate_chat
                    .position(state.vertical_position_chat);
            }
            AppCurrentState::Request => {
                state.character_indexy = state.character_indexy.saturating_sub(1);
            }
        }
    }

    async fn move_horizontal_scroll_left(&mut self) {
        let mut state = self.state.lock().await;
        if state.chat_messages.len() > 0 {
            state.horizontal_position_chat = state.horizontal_position_chat.saturating_sub(1);
        } else {
            state.horizontal_position_commands =
                state.horizontal_position_commands.saturating_sub(1);
        }
    }
    async fn move_horizontal_scroll_reset(&mut self) {
        let mut state = self.state.lock().await;
        state.horizontal_position_chat = 0;
    }
    async fn move_horizontal_scroll_right(&mut self) {
        let mut state = self.state.lock().await;
        if state.chat_messages.len() > 0 {
            state.horizontal_position_chat = state.horizontal_position_chat.saturating_add(1);
        } else {
            state.horizontal_position_commands =
                state.horizontal_position_commands.saturating_add(1);
        }
    }
    async fn write_new_message(&mut self, cmd: PrintCommand) {
        let mut state = self.state.lock().await;
        let lines = cmd
            .message
            .lines() // Split the message into lines
            .map(|line| PrintCommand {
                window: cmd.window,
                message: line.to_string(),
                style: cmd.style.clone(),
                color: cmd.color.clone(),
            })
            .collect::<Vec<PrintCommand>>();
        for line in lines {
            let mut v = Vec::new();
            v.push(line);
            state.messages.push(v);
        }
        state.scrollstate_commands = state
            .scrollstate_commands
            .content_length(state.messages.len());
    }
    async fn write_new_message_raw(&mut self, message: String, style: TextStyle) {
        let mut state = self.state.lock().await;
        let cmd = PrintCommand {
            window: 0,
            message,
            style,
            color: TextColor::White,
        };
        let mut v = Vec::new();
        v.push(cmd);
        state.messages.push(v);
        state.scrollstate_commands = state
            .scrollstate_commands
            .content_length(state.messages.len());
    }
    async fn set_chat_messages(&mut self, cmd: SetChatMessagesCommand) {
        let messages = cmd.chat_messages;
        let mut state = self.state.lock().await;

        let messages = messages
            .iter()
            .map(|m1| {
                m1.iter()
                    .flat_map(|m2| m2.convert_to_printcmd_vec())
                    .collect::<Vec<PrintCommand>>()
            })
            .collect::<Vec<Vec<PrintCommand>>>();
        state.chat_messages = messages;
        state.scrollstate_chat = state
            .scrollstate_chat
            .content_length(state.chat_messages.len());
    }
    async fn set_request_text(&mut self, request_text: String) {
        let mut state = self.state.lock().await;
        state.request_text = request_text.clone();
    }
    async fn set_app_state(&mut self, state: AppCurrentState) {
        self.state.lock().await.app_current_state = state;
    }
    async fn set_chatid(&mut self, chatid: String) {
        let mut state = self.state.lock().await;
        state.chatid = chatid;
    }

    async fn write_new_chat_message(&mut self, cmd: PrintChatCommand) {
        let mut state = self.state.lock().await;
        state.chatid = format!(" Chatting with {} ", cmd.chatid);
        let v = cmd.convert_to_printcmd_vec();
        state.chat_messages.push(v);
        state.scrollstate_chat = state
            .scrollstate_chat
            .content_length(state.chat_messages.len());
    }

    async fn add_last_message(&mut self, cmd: PrintCommand) {
        let mut state = self.state.lock().await;
        if state.messages.len() > 0 {
            if let Some(last) = state.messages.last_mut() {
                last.push(cmd);
            }
        } else {
            let mut v = Vec::new();
            v.push(cmd);
            state.messages.push(v);
        }
    }

    async fn run(&mut self, mut terminal: DefaultTerminal, pipe: &WindowPipe<WindowCommand>) {
        let pipe = pipe.clone();
        let mut app = self.clone();

        // app.set_app_state(AppCurrentState::Request).await;

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
                    Ok(Ok(command)) => match command {
                        WindowCommand::Print(cmd) => {
                            app.add_last_message(cmd).await;
                        }
                        WindowCommand::Println(cmd) => {
                            app.write_new_message(cmd).await;
                        }
                        WindowCommand::ChatClosed(cmd) => {
                            app.write_new_message_raw(cmd.message, TextStyle::Bold)
                                .await;
                            app.set_app_state(AppCurrentState::Commands).await;
                        }
                        WindowCommand::PrintChat(cmd) => {
                            app.set_app_state(AppCurrentState::Chat).await;
                            app.write_new_chat_message(cmd).await;
                        }
                        WindowCommand::SetChatMessages(cmd) => {
                            app.set_chat_messages(cmd).await;
                        }
                        WindowCommand::SetAppState(cmd) => {
                            app.set_app_state(cmd.state).await;
                        }
                        WindowCommand::Request(cmd) => {
                            app.set_app_state(AppCurrentState::Request).await;
                            app.set_request_text(cmd.message).await;
                        }
                        _ => {}
                    },
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
        let app = self.clone();
        let h1 = tokio::spawn(async move {
            let mut should_run;
            {
                should_run = app.should_run().await;
            }
            while should_run {
                let mut state = read_app_state().await.unwrap();

                let _ = terminal.draw(|frame| App::draw(frame, &mut state));
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
                let app_state = app.get_state().await.app_current_state;
                if let Event::Key(key) = event::read().unwrap() {
                    let input_mode;
                    {
                        input_mode = app.get_input_mode().await;
                    }
                    match input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('s') => match app_state {
                                AppCurrentState::Request => {
                                    app.submit_message().await;
                                    app.set_app_state(AppCurrentState::Commands).await;
                                }
                                _ => {}
                            },
                            KeyCode::Char(' ') => {
                                app.set_input_mode(InputMode::Editing).await;
                            }
                            KeyCode::Char('q') => {
                                match app_state {
                                    AppCurrentState::Commands => {
                                        app.set_terminate().await;
                                        app.clear_chat().await;
                                        let _ = tx.send(None).await;
                                    }
                                    _ => {}
                                }

                                if !app.is_in_chat_mode().await {
                                } else {
                                    app.write_new_message_raw(
                                        "Closed the session".to_string(),
                                        TextStyle::Bold,
                                    )
                                    .await;
                                    app.set_chatid("Closing this chat..".to_string()).await;
                                    let _ = tx
                                        .send(Some(WindowCommand::ChatClosed(ChatClosedCommand {
                                            message: "Closing the chat".to_string(),
                                        })))
                                        .await;
                                }

                                app.set_app_state(AppCurrentState::Commands).await;
                            }
                            KeyCode::Up => app.move_vertical_scroll_up().await,
                            KeyCode::Down => app.move_vertical_scroll_down().await,
                            KeyCode::Left => app.move_horizontal_scroll_left().await,
                            KeyCode::Right => app.move_horizontal_scroll_right().await,
                            _ => {}
                        },
                        InputMode::Editing if key.kind == KeyEventKind::Press => {
                            let len = app.get_input_len().await;
                            match key.code {
                                KeyCode::Enter => {
                                    if app_state == AppCurrentState::Commands
                                        || app_state == AppCurrentState::Chat
                                    {
                                        app.submit_message().await;
                                    } else {
                                        app.enter_char('\n').await;
                                    }
                                }
                                KeyCode::Char(to_insert) => app.enter_char(to_insert).await,
                                KeyCode::Backspace => app.delete_char().await,
                                KeyCode::Left => app.move_cursor_left(len).await,
                                KeyCode::Up => app.move_vertical_scroll_up().await,
                                KeyCode::Down => app.move_vertical_scroll_down().await,
                                KeyCode::Right => app.move_cursor_right(len).await,
                                KeyCode::Esc => app.set_input_mode(InputMode::Normal).await,
                                _ => {}
                            }
                        }
                        InputMode::Editing => {}
                    }
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

    fn center(area: Rect, horizontal: Constraint, vertical: Constraint) -> Rect {
        let [area] = Layout::horizontal([horizontal])
            .flex(Flex::Center)
            .areas(area);
        let [area] = Layout::vertical([vertical]).flex(Flex::Center).areas(area);
        area
    }

    fn draw_request(frame: &mut Frame, state: &mut AppState) {
        let _messages = &state.messages;
        let input = &state.input;
        let input_mode = &state.input_mode;
        let request_text = &state.request_text;
        let character_index = state.character_index;
        let character_indexy = state.character_indexy;
        let _chat_messages = &state.chat_messages;
        let _chatid = &state.chatid;
        let vertical = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(4),
        ]);
        let [help_area, help_text_area, input_area] = vertical.areas(frame.area());

        let (msg, style) = match input_mode {
            InputMode::Normal => (
                vec![
                    "Press ".into(),
                    "q".bold(),
                    " to exit without sending the email, ".into(),
                    "Space".bold(),
                    " to write. ".into(),
                    "Press ".into(),
                    "s".bold(),
                    " to send.".into(),
                ],
                Style::default().add_modifier(Modifier::RAPID_BLINK),
            ),
            InputMode::Editing => (
                vec![
                    "Press ".into(),
                    "Esc".bold(),
                    " to stop writing, ".into(),
                    "Enter".bold(),
                    " to submit the message".into(),
                ],
                Style::default(),
            ),
        };
        let text = Text::from(Line::from(msg)).patch_style(style);
        let help_message = Paragraph::new(text.clone());
        let area = Self::center(
            help_area,
            Constraint::Length(text.clone().width() as u16),
            Constraint::Length(1),
        );
        frame.render_widget(help_message, area);

        let text = Text::from(Line::from("To give the email a subject title, write: 'Subject: ' and you title following there somewhere in the mail.")).patch_style(Style::default().add_modifier(Modifier::ITALIC).dark_gray());
        let help_message = Paragraph::new(text.clone());
        let area = Self::center(
            help_text_area,
            Constraint::Length(text.clone().width() as u16),
            Constraint::Length(1),
        );
        frame.render_widget(help_message, area);

        let input = Paragraph::new(input.as_str())
            .style(match input_mode {
                InputMode::Normal => Style::default(),
                InputMode::Editing => Style::default().fg(Color::Yellow),
            })
            .block(Block::bordered().title(request_text.as_str()));
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
                input_area.y + character_indexy as u16 + 1,
            )),
        }
    }

    fn draw_commands_section(frame: &mut Frame, state: &mut AppState) {
        let messages = &state.messages;
        let input = &state.input;
        let input_mode = &state.input_mode;
        let character_index = state.character_index;
        let _chat_messages = &state.chat_messages;
        let _chatid = &state.chatid;
        let vertical = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ]);
        let [help_area, input_area, messages_area] = vertical.areas(frame.area());
        let (msg, style) = match input_mode {
            InputMode::Normal => (
                vec![
                    "Press ".into(),
                    "q".bold(),
                    " to exit, ".into(),
                    "Space".bold(),
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
        let help_message = Paragraph::new(text.clone());
        let area = Self::center(
            help_area,
            Constraint::Length(text.clone().width() as u16),
            Constraint::Length(1),
        );

        frame.render_widget(help_message, area);

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

        let mut messages: Vec<Line> = messages
            .iter()
            .map(|m| {
                Line::from(
                    m.iter()
                        .map(|msg| {
                            let message = &msg.message;
                            let style = &msg.style;
                            let color = &msg.color;
                            let mut s = Span::raw(format!("{message}"));
                            match style {
                                TextStyle::Normal => {}
                                TextStyle::Italic => {
                                    s = s.italic();
                                }
                                TextStyle::Bold => {
                                    s = s.bold();
                                }
                                TextStyle::Blinking => {
                                    s = s.add_modifier(Modifier::RAPID_BLINK);
                                }
                            }

                            match color {
                                TextColor::White => s = s.white(),
                                TextColor::Green => s = s.green(),
                                TextColor::Blue => s = s.blue(),
                                TextColor::Red => s = s.red(),
                                TextColor::Gray => s = s.gray(),
                                TextColor::DarkGray => s = s.dark_gray(),
                                TextColor::Yellow => s = s.yellow(),
                                TextColor::Magenta => s = s.magenta(),
                                TextColor::Black => s = s.black(),
                                TextColor::LightRed => s = s.light_red(),
                                TextColor::LightGreen => s = s.light_green(),
                                TextColor::LightYellow => s = s.light_yellow(),
                                TextColor::LightBlue => s = s.light_blue(),
                                TextColor::LightMagenta => s = s.light_magenta(),
                                TextColor::LightCyan => s = s.light_cyan(),
                            };
                            s
                        })
                        .collect::<Vec<Span>>(),
                )
            })
            .collect();
        let height = messages_area.height as usize;
        if messages.len() >= height {
            let start_index = messages.len() - height + 2;
            messages = (&messages[start_index..]).to_vec();
        }
        let messages = Paragraph::new(messages)
            .block(Block::bordered().title("Commands"))
            .scroll((
                state.vertical_position_commands.try_into().unwrap(),
                state.horizontal_position_chat.try_into().unwrap(),
            ));
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        frame.render_widget(messages, messages_area);
        frame.render_stateful_widget(
            scrollbar,
            messages_area.inner(Margin {
                // using an inner vertical margin of 1 unit makes the scrollbar inside the block
                vertical: 1,
                horizontal: 0,
            }),
            &mut state.scrollstate_commands,
        );
    }

    fn draw_commands_chat(frame: &mut Frame, state: &mut AppState) {
        let _messages = &state.messages;
        let input = &state.input;
        let input_mode = &state.input_mode;
        let character_index = state.character_index;
        let chat_messages = &state.chat_messages;
        let chatid = &state.chatid;
        let vertical = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(3),
        ]);
        let [chat_area, help_area, input_area] = vertical.areas(frame.area());
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

        let messages: Vec<Line> = chat_messages
            .iter()
            .map(|m| {
                Line::from(
                    m.iter()
                        .map(|msg| {
                            let message = &msg.message;
                            let style = &msg.style;
                            let color = &msg.color;
                            let mut s = Span::raw(format!("{message}"));
                            match style {
                                TextStyle::Normal => {}
                                TextStyle::Italic => {
                                    s = s.italic();
                                }
                                TextStyle::Bold => {
                                    s = s.bold();
                                }
                                TextStyle::Blinking => {
                                    s = s.add_modifier(Modifier::RAPID_BLINK);
                                }
                            }

                            match color {
                                TextColor::White => s = s.white(),
                                TextColor::Green => s = s.green(),
                                TextColor::Blue => s = s.blue(),
                                TextColor::Red => s = s.red(),
                                TextColor::Gray => s = s.gray(),
                                TextColor::DarkGray => s = s.dark_gray(),
                                TextColor::Yellow => s = s.yellow(),
                                TextColor::Magenta => s = s.magenta(),
                                TextColor::Black => s = s.black(),
                                TextColor::LightRed => s = s.light_red(),
                                TextColor::LightGreen => s = s.light_green(),
                                TextColor::LightYellow => s = s.light_yellow(),
                                TextColor::LightBlue => s = s.light_blue(),
                                TextColor::LightMagenta => s = s.light_magenta(),
                                TextColor::LightCyan => s = s.light_cyan(),
                            };
                            s
                        })
                        .collect::<Vec<Span>>(),
                )
            })
            .collect();
        let messages = Paragraph::new(messages)
            .block(Block::bordered().title(format!("{}", chatid)))
            .scroll((
                state.vertical_position_chat.try_into().unwrap(),
                state.horizontal_position_chat.try_into().unwrap(),
            ));

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        frame.render_widget(messages, chat_area);

        frame.render_stateful_widget(
            scrollbar,
            chat_area.inner(Margin {
                // using an inner vertical margin of 1 unit makes the scrollbar inside the block
                vertical: 1,
                horizontal: 0,
            }),
            &mut state.scrollstate_chat,
        );
    }

    fn draw(frame: &mut Frame, state: &mut AppState) {
        match state.app_current_state {
            AppCurrentState::Commands => {
                Self::draw_commands_section(frame, state);
            }
            AppCurrentState::Chat => {
                Self::draw_commands_chat(frame, state);
            }
            AppCurrentState::Request => {
                Self::draw_request(frame, state);
            }
        }
    }
}

static STATE: OnceCell<Arc<WindowPipe<AppState>>> = OnceCell::const_new();

async fn initialize_global_values() {
    // Directly initialize the GLOBAL_VALUE using `init`
    let _ = STATE.set(Arc::new(WindowPipe::<AppState>::new()));
}

async fn read_app_state() -> Result<AppState, ()> {
    match STATE.get().unwrap().read().await {
        Ok(cmd) => Ok(cmd),
        Err(_) => Err(()),
    }
}

async fn send_app_state(state: AppState) {
    let _ = STATE.get().unwrap().send(state).await;
}

pub fn format_chat_msg<P: CrypticalID + Cryptical>(
    message: &str,
    encro: &P,
) -> (String, String, String) {
    (
        message.into(),
        encro.get_userid(),
        encro.get_public_key_fingerprint(),
    )
}

pub fn format_chat_msg_fmt(message: &str, userid: &str, fingerprint: &str) -> (String, String) {
    let time = get_current_datetime();
    let chat_view = format!(
        "{} - {} ({}): {}",
        time,
        userid,
        short_fingerprint(fingerprint),
        message
    );
    let chat_id = userid.to_string();
    (chat_id, chat_view)
}
