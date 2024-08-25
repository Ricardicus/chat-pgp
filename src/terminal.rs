use ncurses::*;
use std::collections::HashMap;
use std::marker::PhantomData;

pub struct WindowManager {
    windows: HashMap<usize, WINDOW>,
    num_windows: usize,
    _marker: PhantomData<*const ()>, // Marker for Send and Sync
}

unsafe impl Send for WindowManager {}
unsafe impl Sync for WindowManager {}

impl WindowManager {
    // Initialize the window manager with a specified number of windows
    pub fn init(num_windows: usize) -> WindowManager {
        // Initialize ncurses
        initscr();
        cbreak();
        noecho();
        keypad(stdscr(), true); // Enable keypad input
        refresh(); // Refresh the standard screen to ensure it's initialized

        let mut windows = HashMap::new();
        let mut max_y = 0;
        let mut max_x = 0;
        getmaxyx(stdscr(), &mut max_y, &mut max_x);

        // Calculate window height and width
        let win_height = max_y / num_windows as i32;
        let win_width = max_x;

        // Create the specified number of windows
        for i in 0..num_windows {
            let start_y = i as i32 * win_height;
            let win = newwin(win_height, win_width, start_y, 0);
            scrollok(win, true); // Enable scrolling for the window
            box_(win, 0, 0); // Draw a box around the window
            wrefresh(win); // Refresh the window to apply the box
            windows.insert(i, win);
        }

        WindowManager {
            windows,
            num_windows,
            _marker: PhantomData,
        }
    }

    // Print a message to a specific window
    pub fn printw(&self, window_number: usize, message: &str) {
        if let Some(win) = self.windows.get(&window_number) {
            // Print the message in the window
            mvwprintw(*win, getcury(*win) + 1, 1, message);
            wrefresh(*win); // Refresh the window to display the new content
        } else {
            println!("Window number {} does not exist.", window_number);
        }
    }

    // Make window interactive
    pub fn getch(&self, window_number: usize, prompt: &str) -> String {
        if let Some(win) = self.windows.get(&window_number) {
            loop {
                // Move the cursor to just inside the box, 1 line down, 1 column in
                wmove(*win, getcury(*win), 1);
                self.printw(window_number, prompt);
                wmove(*win, getcury(*win), (prompt.len() + 1) as i32);
                wrefresh(*win);

                let mut input = String::new();
                nocbreak();
                echo();
                curs_set(CURSOR_VISIBILITY::CURSOR_VISIBLE);

                // Handle user input
                let mut ch = wgetch(*win);
                while ch != '\n' as i32 {
                    if ch == KEY_BACKSPACE || ch == 127 {
                        if !input.is_empty() {
                            input.pop();
                            wdelch(*win);
                        }
                    } else {
                        input.push(char::from_u32(ch as u32).unwrap());
                    }
                    wrefresh(*win);
                    ch = wgetch(*win);
                }

                // Redraw the box after every input to maintain the boundaries
                box_(*win, 0, 0);
                wrefresh(*win);

                // Exit condition (optional)
                return input;
            }
        } else {
            println!("Window number {} does not exist.", window_number);
            "".to_string()
        }
    }

    // Clean up ncurses
    pub fn cleanup(&self) {
        for (_, win) in &self.windows {
            delwin(*win);
        }
        endwin(); // End ncurses mode
    }
}

fn main() {
    let mut manager = WindowManager::init(2);

    manager.printw(0, "Window 1:");
    manager.printw(1, "Window 2: Interactive");

    let p = ">> ";
    manager.getch(1, &p);

    manager.cleanup(); // Clean up ncurses
}