use std::sync::Arc;

use tokio::sync::mpsc;

async fn student(id: i32, tx: Arc<mpsc::Sender<String>>) {
    println!("student {} is getting their hw.", id);
    tx.send(format!("student {}'s hw !", id)).await.unwrap();
}

async fn teacher(mut rc: mpsc::Receiver<String>) -> Vec<String> {
    let mut homeworks = Vec::new();
    while let Some(hw) = rc.recv().await {
        println!("{hw}");
        homeworks.push(hw);
    }
    homeworks
}

#[tokio::main]
async fn main() {
    let (tx, rc): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel(100);
    let ch_arc: Arc<mpsc::Sender<String>> = Arc::new(tx);

    for i in 0..10 {
        tokio::task::spawn(student(i, ch_arc.clone()));
    }

    // drop(ch_arc); // this is the fix

    let hws = teacher(rc).await;
    println!("{:?}", hws);
}
