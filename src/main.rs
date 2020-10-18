use std::io;
extern crate bitcoin;

use elements::bitcoin_hashes::hex::FromHex;
use elements::{confidential, AssetId};
use miniscript::descriptor::covenants::CovenantCreationCtx;
use std::io::Write;
use std::str::FromStr;

use elements::bitcoin_hashes::hex::ToHex;
use elements::encode::serialize;

mod wallet;
use std::fs::File;
use std::io::BufRead;
fn main() {
    println!("Covenants in Elements demo!");

    let mut wallet;
    loop {
        print!("$: ");
        io::stdout().flush().unwrap();

        // --snip--

        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let input = input.trim();
        let mut inp_iter = input.split(" ");
        let cmd = match inp_iter.next() {
            Some(x) => x,
            None => continue,
        };
        let args: Vec<&str> = inp_iter.collect();
        match cmd {
            "init" => {
                let fee_collector_srv_pk = bitcoin::PublicKey::from_str(
                    "02d34800ac89c2f27ae8938c2ea370bd63d5d47926d71243deb492966d1e37e355",
                )
                .unwrap();
                let timestamp_srv_pk = bitcoin::PublicKey::from_str(
                    "03642e750575c0692c7c6984f5eb3ceaa81a619820eee2290caeeb7affc303abdb",
                )
                .unwrap();
                let fee_collector_wpkh = match elements::Address::from_str(args[1]) {
                    Ok(addr) => addr.script_pubkey(),
                    Err(e) => {
                        println!("Expecting BECH32 p2wpkh address: {}", e);
                        continue;
                    }
                };
                let creation_ctx = CovenantCreationCtx {
                    traded_asset: confidential::Asset::Explicit(match AssetId::from_str(args[0]) {
                        Ok(x) => x,
                        Err(e) => {
                            println!("Invalid asset id {}", e);
                            continue;
                        }
                    }),
                    fee_collector_wpkh: fee_collector_wpkh,
                    fee_collector_srv_pk: fee_collector_srv_pk,
                    timestamp_srv_pk: timestamp_srv_pk,
                };
                wallet = wallet::WalletCtx::init_wallet(creation_ctx);
                break;
            }
            _ => println!("Must initialize wallet before using, use init"),
        }
    }
    loop {
        print!("$: ");
        io::stdout().flush().unwrap();
        // --snip--

        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let input = input.trim();
        let mut inp_iter = input.split(" ");
        let cmd = inp_iter.next().unwrap();
        let args: Vec<&str> = inp_iter.collect();

        match cmd {
            "getnewassetaddress" => println!("{}", wallet.getnewasset_address()),
            "getnewbtcaddress" => println!("{}", wallet.getnewbtc_address()),
            "getbalance" => wallet.getbalance(),
            "recieve" => {
                let file = match File::open(args[0]) {
                    Ok(f) => f,
                    Err(e) => {
                        println!("File not found: {}", e);
                        continue;
                    }
                };
                //assums correct content of the files
                let tx_hex = io::BufReader::new(file)
                    .lines()
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap();
                let tx_bytes: Vec<u8> = FromHex::from_hex(&tx_hex).unwrap();
                wallet.recieve(&tx_bytes);
            }
            "sendasset" => {
                let reciever_pk = match bitcoin::PublicKey::from_str(args[0]) {
                    Ok(pk) => pk,
                    Err(e) => {
                        println!("Expected pubkey {}", e);
                        continue;
                    }
                };
                let amt: f64 = match f64::from_str(args[1]) {
                    Ok(d) => d * 100_000_000.0, // may be slightly off, but ok.
                    Err(e) => {
                        println!("Expected Decimal amount in asset/btc: {}", e);
                        continue;
                    }
                };
                let tx = wallet.sendasset(reciever_pk, amt.ceil() as u64);
                println!("{}", serialize(&tx).to_hex());
            }
            "cheat" => {
                let reciever_pk = match bitcoin::PublicKey::from_str(args[0]) {
                    Ok(pk) => pk,
                    Err(e) => {
                        println!("Expected pubkey {}", e);
                        continue;
                    }
                };
                let amt: f64 = match f64::from_str(args[1]) {
                    Ok(d) => d * 100_000_000.0, // may be slightly off, but ok.
                    Err(e) => {
                        println!("Expected Decimal amount in asset/btc: {}", e);
                        continue;
                    }
                };
                let mut tx = wallet.sendasset(reciever_pk, amt.ceil() as u64);
                let x = wallet::get_explicit(tx.output[0].value) / 2; // should make fee err
                tx.output[0].value = perturb_exp(tx.output[0].value, x, true);
                tx.output[2].value = perturb_exp(tx.output[2].value, x, false);
                println!("{}", serialize(&tx).to_hex());
            }
            _ => println!("Unrecognized input"),
        }
    }
}

fn perturb_exp(
    c: elements::confidential::Value,
    x: u64,
    sign: bool,
) -> elements::confidential::Value {
    let v = wallet::get_explicit(c);
    if sign {
        elements::confidential::Value::Explicit(v - x)
    } else {
        elements::confidential::Value::Explicit(v + x)
    }
}
