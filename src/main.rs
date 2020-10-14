use std::io;
extern crate bitcoin;

use elements::bitcoin_hashes::hex::FromHex;
use elements::{confidential, AssetId, Script};
use miniscript::descriptor::covenants::CovenantCreationCtx;
use std::io::Write;
use std::str::FromStr;

mod wallet;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;
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
        let cmd = inp_iter.next().unwrap();
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
                let fee_collector_wsh: Vec<u8> = FromHex::from_hex(args[1]).unwrap();
                let creation_ctx = CovenantCreationCtx {
                    traded_asset: confidential::Asset::Explicit(
                        AssetId::from_str(args[0]).unwrap(),
                    ),
                    fee_collector_wsh: Script::from(fee_collector_wsh),
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
                let file = File::open(args[0]).unwrap();
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
                let reciever_pk = bitcoin::PublicKey::from_str(args[0]).unwrap();
                let amt = u64::from_str(args[1]).unwrap();
                wallet.sendasset(reciever_pk, amt);
            }
            _ => println!("Unrecognized input"),
        }
    }
}
