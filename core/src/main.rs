
mod crypto;
mod block;
mod chain;
mod state;
mod tx;

use chain::Blockchain;
use std::io;


fn main() {
    let mut blockchain = Blockchain::new(4);

    loop {
        println!("\nChoose an option");
        println!("1. Add Transaction");
        println!("2. Mine Transactions");
        println!("3. View Blockchain");
        println!("4. Validate Blockchain");
        println!("5. Save Blockchain");
        println!("6. Load Blockchain");
        println!("7. Exit\n");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                println!("Enter sender:");
                let mut sender = String::new();
                io::stdin().read_line(&mut sender).unwrap();

                println!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();

                println!("Enter amount:");
                let mut amount = String::new();
                io::stdin().read_line(&mut amount).unwrap();
                let amount: f64 = amount.trim().parse().expect("Invalid amount input");

                blockchain.add_transaction(sender.trim().to_string(), recipient.trim().to_string(), amount);
                println!("Transaction added!");
            }
            "2" => {
                println!("Enter miner address:");
                let mut miner = String::new();
                io::stdin().read_line(&mut miner).unwrap();

                blockchain.mine_pending_transactions(miner.trim().to_string());
                println!("Transactions mined!");
            }
            "3" => {
                for block in &blockchain.chain {
                    println!("{:?}", block);
                }
            }
            "4" => {
                if blockchain.is_valid() {
                    println!("Blockchain is valid.");
                } else {
                    println!("Blockchain is invalid!");
                }
            }
            "5" => {
                println!("Enter filename to save:");
                let mut filename = String::new();
                io::stdin().read_line(&mut filename).unwrap();

                blockchain.save_to_file(filename.trim());
                println!("Blockchain saved!");
            }
            "6" => {
                println!("Enter filename to load:");
                let mut filename = String::new();
                io::stdin().read_line(&mut filename).unwrap();

                blockchain = Blockchain::load_from_file(filename.trim());
                println!("Blockchain loaded!");
            }
            "7" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid choice. Try again."),
        }
    }
}
