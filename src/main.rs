use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Result;

use tindercrypt::cryptors::RingCryptor;

use structopt::StructOpt;

use cli_table::{format::Justify, print_stdout, Cell, Style, Table, WithTitle};

#[derive(Serialize, Deserialize, Debug)]
struct Account {
    url: String,
    login: String,
    password: String,
    info: String,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "basic")]
struct CliConfig {
    #[structopt(short, long)]
    passphrase: String,
    #[structopt()]
    path: Option<String>,
    #[structopt(short, long)]
    get: Option<String>,
}

#[derive(Debug)]
struct Config {
    passphrase: String,
    path: PathBuf,
    get: Option<String>,
}

fn parse_config() -> Config {
    let cli: CliConfig = CliConfig::from_args();
    let path: PathBuf;
    match cli.path {
        Some(p) => {
            path = PathBuf::from(p);
            return Config {
                passphrase: cli.passphrase,
                path,
                get: cli.get,
            };
        }
        None => path = home::home_dir().expect("impossible to find home directory"),
    }
    Config {
        passphrase: cli.passphrase,
        path: path.join("archive.fess"),
        get: cli.get,
    }
}

fn serialize_account(acc: &Account) -> Result<String> {
    let data = serde_json::to_string(&acc)?;
    Ok(data)
}

fn serialize_accounts(accs: HashMap<String, Account>) -> Result<String> {
    let data = serde_json::to_string(&accs)?;
    Ok(data)
}

fn deserialize_accounts(data: String) -> HashMap<String, Account> {
    let accs: HashMap<String, Account> = serde_json::from_str(&data).expect("Error unwrappig");
    accs
}

fn encrypt(data: String, passphrase: &String) -> Vec<u8> {
    let data_bytes = data.as_bytes();
    let pass_bytes = passphrase.as_bytes();
    let cryptor = RingCryptor::new();
    let encrypted = cryptor
        .seal_with_passphrase(pass_bytes, data_bytes)
        .expect("error in encryption");
    encrypted
}

fn decrypt(data: Vec<u8>, passphrase: &String) -> String {
    let cryptor = RingCryptor::new();
    let decrypted_bytes = cryptor
        .open(passphrase.as_bytes(), &data)
        .expect("Error decrypting");
    let text = String::from_utf8(decrypted_bytes).expect("Error decoding decrypted data");
    text
}

fn write_json_to_disk(data: Vec<u8>, path: &PathBuf) {
    let mut file = match File::create(path) {
        Err(why) => panic!("Could not create file {:?}", why),
        Ok(file) => file,
    };
    match file.write_all(&data) {
        Err(_) => panic!("error writing to file"),
        Ok(_) => println!("data succesfully wrote"),
    };
}

fn read_encryted_data_from_disk(path: &PathBuf) -> Option<Vec<u8>> {
    let mut file = match File::open(&path) {
        Err(why) => return None,
        Ok(file) => file,
    };
    let metadata = file.metadata().expect("Error redaing metadata");
    let mut data: Vec<u8> = vec![0; metadata.len() as usize];
    match file.read(data.as_mut_slice()) {
        Err(why) => panic!("error reading file: {:?}", why),
        Ok(r) => {},
    }
    Some(data)
}

fn get_user_input(message: &str) -> String {
    println!("{}", message);
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("failed to read user input");
    input = input.trim().to_string();
    input
}

fn get_account() -> Account {
    let account_name = get_user_input("Input account name (must be unique)");
    let login = get_user_input("Input login");
    let password = get_user_input("Input password");
    let info = get_user_input("Input any additional information");
    Account {
        url: account_name,
        login,
        password,
        info,
    }
}

fn print_account(acc: &Account) {
    let table = vec![
        vec!["URL".cell(), acc.url.clone().cell()],
        vec!["Login".cell(), acc.login.clone().cell()],
        vec!["Password".cell(), acc.password.clone().cell()],
        vec!["Information".cell(), acc.info.clone().cell()],
    ].table();
    print_stdout(table);
}

fn process_get(passphrase: &String, path: &PathBuf, acc_name: String) {
    let data = match read_encryted_data_from_disk(path) {
        Some(data) => data,
        None => {
            println!("Data file does not exist");
            return;
        }
    };
    let text = decrypt(data, passphrase);
    let accs = deserialize_accounts(text);
    match accs.get(&acc_name) {
        Some(account) => {
            print_account(account);
        }
        None => println!("Account not found"),
    }
}

fn process_set(passphrase: &String, path: &PathBuf) {
    let account = get_account();
    let mut accs: HashMap<String, Account>;
    match read_encryted_data_from_disk(&path) {
        Some(data) => {
            let text = decrypt(data, &passphrase);
            accs = deserialize_accounts(text);
        }
        None => accs = HashMap::new(),
    };
    accs.insert(account.url.clone(), account);
    let js = serialize_accounts(accs).expect("error serializing");
    let encrypted = encrypt(js, passphrase);
    write_json_to_disk(encrypted, path);
}

fn main() {
    let cli = parse_config();
    let passphrase = cli.passphrase;
    let path = cli.path;
    match cli.get {
        Some(acc_name) => process_get(&passphrase, &path, acc_name),
        None => process_set(&passphrase, &path),
    };
}
