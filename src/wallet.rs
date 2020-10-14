// Maintain Wallet state
use bitcoin::secp256k1;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Network;
use elements::bitcoin_hashes::hex::ToHex;
use elements::bitcoin_hashes::{Hash, HashEngine};
use elements::encode::{deserialize, serialize};
use elements::{confidential, Script};
use elements::{AssetIssuance, OutPoint, SigHash, TxIn, TxInWitness, TxOut};
use miniscript::descriptor::Descriptor;
use std::str::FromStr;

use miniscript::descriptor::covenants::{
    CovenantAddressCtx, CovenantCreationCtx, CovenantCtx, CoventSpendCtx,
};

#[derive(Debug, Clone)]
pub struct WalletCtx {
    cursor_bitcoin: ChildNumber,
    cursor_asset: ChildNumber,
    derivation_path_btc: DerivationPath,
    derivation_path_asset: DerivationPath,

    priv_key: ExtendedPrivKey,
    pub_key: ExtendedPubKey,

    cov_creation_info: CovenantCreationCtx,
    walletdb: WalletDB,
}

#[derive(Debug, Clone)]
pub struct WalletDB {
    btc_utxos: Vec<UTXOinfo>,
    asset_utxos: Vec<UTXOinfo>,
}

#[derive(Debug, Clone)]
pub struct UTXOinfo {
    txout: TxOut,
    sk: bitcoin::PrivateKey,
    outpoint: elements::OutPoint,
}

impl WalletCtx {
    pub fn init_wallet(creation_ctx: CovenantCreationCtx) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let seed = "This is not secure!".as_bytes();
        let network = Network::Regtest;
        let sk = ExtendedPrivKey::new_master(network, seed).unwrap();
        let pk = ExtendedPubKey::from_private(&secp, &sk);

        let btc_path = DerivationPath::from_str("m/0'").unwrap();
        let asset_path = DerivationPath::from_str("m/1'").unwrap();

        let wallet = WalletCtx {
            cursor_asset: ChildNumber::from_hardened_idx(0).unwrap(),
            cursor_bitcoin: ChildNumber::from_hardened_idx(0).unwrap(),
            derivation_path_btc: btc_path,
            derivation_path_asset: asset_path,
            priv_key: sk,
            pub_key: pk,
            cov_creation_info: creation_ctx,
            walletdb: WalletDB {
                btc_utxos: Vec::<UTXOinfo>::new(),
                asset_utxos: Vec::<UTXOinfo>::new(),
            },
        };
        wallet
        // // Check derivation convenience method for ExtendedPrivKey
        // assert_eq!(
        //     &sk.derive_priv(secp, &path).unwrap().to_string()[..],
        //     expected_sk
        // );

        // // Check derivation convenience method for ExtendedPubKey, should error
        // // appropriately if any ChildNumber is hardened
        // if path.0.iter().any(|cnum| cnum.is_hardened()) {
        //     assert_eq!(
        //         pk.derive_pub(secp, &path),
        //         Err(Error::CannotDeriveFromHardenedKey)
        //     );
        // } else {
        //     assert_eq!(
        //         &pk.derive_pub(secp, &path).unwrap().to_string()[..],
        //         expected_pk
        //     );
        // }

        // // Derive keys, checking hardened and non-hardened derivation one-by-one
        // for &num in path.0.iter() {
        //     sk = sk.ckd_priv(secp, num).unwrap();
        //     match num {
        //         Normal {..} => {
        //             let pk2 = pk.ckd_pub(secp, num).unwrap();
        //             pk = ExtendedPubKey::from_private(secp, &sk);
        //             assert_eq!(pk, pk2);
        //         }
        //         Hardened {..} => {
        //             assert_eq!(
        //                 pk.ckd_pub(secp, num),
        //                 Err(Error::CannotDeriveFromHardenedKey)
        //             );
        //             pk = ExtendedPubKey::from_private(secp, &sk);
        //         }
        //     }
    }

    pub fn getnewbtc_address(&mut self) -> elements::Address {
        let path = self.derivation_path_btc.child(self.cursor_bitcoin);
        let secp = secp256k1::Secp256k1::new();
        let sk = self.priv_key.derive_priv(&secp, &path).unwrap();
        let pk = ExtendedPubKey::from_private(&secp, &sk);

        // Update the cursor
        self.cursor_bitcoin = self.cursor_bitcoin.increment().unwrap();

        elements::Address::p2wpkh(&pk.public_key, None, &elements::AddressParams::ELEMENTS)
    }

    pub fn getnewasset_address(&mut self) -> elements::Address {
        let path = self.derivation_path_asset.child(self.cursor_asset);
        let secp = secp256k1::Secp256k1::new();
        let sk = self.priv_key.derive_priv(&secp, &path).unwrap();
        let pk = ExtendedPubKey::from_private(&secp, &sk);

        // Update the cursor
        self.cursor_asset = self.cursor_asset.increment().unwrap();
        //Create a covenant descriptor

        let desc_cov = Descriptor::Cov(CovenantCtx {
            commit_ctx: CovenantAddressCtx {
                cov_info: self.cov_creation_info.clone(),
                redeem_pk: pk.public_key,
            },
            spend_ctx: None,
        });
        let script_pubkey = desc_cov.witness_script();
        println!("{}", script_pubkey.to_hex());
        let addr =
            elements::Address::p2wsh(&script_pubkey, None, &elements::AddressParams::ELEMENTS);
        println!("{}", addr.script_pubkey());
        addr
    }

    pub fn recieve(&mut self, tx: &[u8]) {
        let tx: elements::Transaction = deserialize(tx).unwrap();
        let secp = secp256k1::Secp256k1::new();
        for (i, output) in tx.output.iter().enumerate() {
            for path in self.derivation_path_btc.hardened_children().take(1000) {
                let ext_sk = self.priv_key.derive_priv(&secp, &path).unwrap();
                let pk = bitcoin::PublicKey::from_private_key(&secp, &ext_sk.private_key);
                let script_pubkey =
                    elements::Address::p2wpkh(&pk, None, &elements::AddressParams::ELEMENTS)
                        .script_pubkey();
                if script_pubkey == output.script_pubkey {
                    let utxo_info = UTXOinfo {
                        txout: output.clone(),
                        sk: ext_sk.private_key,
                        outpoint: elements::OutPoint {
                            txid: tx.txid(),
                            vout: i as u32,
                        },
                    };
                    self.walletdb.btc_utxos.push(utxo_info);
                }
            }

            for path in self.derivation_path_asset.hardened_children().take(1000) {
                let ext_sk = self.priv_key.derive_priv(&secp, &path).unwrap();
                let pk = bitcoin::PublicKey::from_private_key(&secp, &ext_sk.private_key);
                let desc_cov = Descriptor::Cov(CovenantCtx {
                    commit_ctx: CovenantAddressCtx {
                        cov_info: self.cov_creation_info.clone(),
                        redeem_pk: pk,
                    },
                    spend_ctx: None,
                });
                let script_pubkey = desc_cov.witness_script().to_v0_p2wsh();
                if script_pubkey == output.script_pubkey {
                    let utxo_info = UTXOinfo {
                        txout: output.clone(),
                        sk: ext_sk.private_key,
                        outpoint: elements::OutPoint {
                            txid: tx.txid(),
                            vout: i as u32,
                        },
                    };
                    self.walletdb.asset_utxos.push(utxo_info);
                }
            }
        }
    }

    pub fn getbalance(&self) {
        let mut btc_bal: u64 = 0;
        let mut asset_bal: u64 = 0;
        for utxo in &self.walletdb.btc_utxos {
            if let confidential::Value::Explicit(v) = utxo.txout.value {
                btc_bal += v;
            } else {
                unreachable!("Only explicit supported");
            }
        }

        for utxo in &self.walletdb.asset_utxos {
            if let confidential::Value::Explicit(v) = utxo.txout.value {
                asset_bal += v;
            } else {
                unreachable!("Only explicit supported");
            }
        }

        println!("BTC balance: {}", btc_bal);
        println!("asset balance: {}", asset_bal);
    }

    pub fn sendasset(&mut self, reciver_pk: bitcoin::PublicKey, amt: u64) {
        // Create the sender context
        let mut tx = elements::Transaction::default();
        tx.version = 2;
        // Select a asset_value
        // Naive algorithm: select the first input that has value more than required amt
        let mut spend_utxo = None;
        let mut asset_utxo_idx = None;
        for (i, utxo) in self.walletdb.asset_utxos.iter().enumerate() {
            if let confidential::Value::Explicit(v) = utxo.txout.value {
                if v >= amt {
                    spend_utxo = Some(utxo);
                    asset_utxo_idx = Some(i);
                    break;
                }
            }
        }
        if spend_utxo.is_none() {
            panic!("No single utxo to satisfy");
        }
        let utxo = spend_utxo.unwrap();
        let asset_utxo_idx = asset_utxo_idx.unwrap();
        let inp = txin_from_outpoint(utxo.outpoint);
        tx.input.push(inp);

        // Select change output
        // Naive algorithm: select the first input that has value more than required amt
        let btc_utxo = &self.walletdb.btc_utxos[0];
        let btc_inp = txin_from_outpoint(btc_utxo.outpoint);
        tx.input.push(btc_inp);

        // Get the fee rate here
        let fee_rate = 200;
        let utxo_amt = get_explicit(utxo.txout.value);

        let spend_ctx = CoventSpendCtx {
            tx: tx,
            index: 0,
            receiver_pk: reciver_pk,
            sent_amt: confidential::Value::Explicit(amt),
            fee_amt: confidential::Value::Explicit(amt / fee_rate),
            change_amt: confidential::Value::Explicit(utxo_amt - amt - amt / fee_rate),
            tx_fee_btc: btc_utxo.txout.value,
            prev_utxo_amt: utxo.txout.value,

            redeem_priv_key: utxo.sk,

            // Sigs and msgs
            timestamp_srv_msg: vec![],
            timestamp_srv_sig: vec![],
            fee_srv_msg: vec![],
            fee_srv_sig: vec![],
        };

        let secp = secp256k1::Secp256k1::new();
        let mut cov_ctx = CovenantCtx {
            commit_ctx: CovenantAddressCtx {
                cov_info: self.cov_creation_info.clone(),
                redeem_pk: bitcoin::PublicKey::from_private_key(&secp, &utxo.sk),
            },
            spend_ctx: Some(spend_ctx),
        };
        let wit = cov_ctx.finalize();
        let mut tx = cov_ctx.spend_ctx.unwrap().tx;
        tx.input[0].witness.script_witness = wit;
        // finalize the bitcoin input
        let btc_pk = bitcoin::PublicKey::from_private_key(&secp, &btc_utxo.sk);
        let btc_desc = Descriptor::Wpkh(btc_pk);
        let mut sighash_cache = elements::bip143::SigHashCache::new(&tx);
        let sighash = sighash_cache.signature_hash(
            1,
            &btc_desc.script_code(),
            btc_utxo.txout.value,
            elements::SigHashType::All,
        );
        let secp = secp256k1::Secp256k1::new();
        let sighash_msg: Vec<u8> = sighash.into_iter().flatten().collect();
        let mut eng = SigHash::engine();
        eng.input(&sighash_msg);
        let sighash_u256 = SigHash::from_engine(eng);

        let sig = secp.sign(
            &bitcoin::secp256k1::Message::from_slice(&sighash_u256[..]).unwrap(),
            &btc_utxo.sk.key,
        );
        let mut redeem_sig = Vec::from(sig.serialize_der().as_ref());
        redeem_sig.push(1u8);

        tx.input[1].witness.script_witness = vec![redeem_sig, btc_pk.to_bytes()];

        // Remove the utxos
        self.walletdb.btc_utxos.remove(0);
        self.walletdb.asset_utxos.remove(asset_utxo_idx);
        println!("{}", serialize(&tx).to_hex());
    }
}

pub fn txin_from_outpoint(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        sequence: 0xfffffffe,
        is_pegin: false,
        has_issuance: false,
        // perhaps make this an option in elements upstream?
        asset_issuance: AssetIssuance {
            asset_blinding_nonce: [0; 32],
            asset_entropy: [0; 32],
            amount: confidential::Value::Null,
            inflation_keys: confidential::Value::Null,
        },
        script_sig: Script::new(),
        witness: TxInWitness {
            amount_rangeproof: vec![],
            inflation_keys_rangeproof: vec![],
            script_witness: vec![],
            pegin_witness: vec![],
        },
    }
}

fn get_explicit(amt: confidential::Value) -> u64 {
    if let confidential::Value::Explicit(x) = amt {
        x
    } else {
        panic!("Must have explicit amounts");
    }
}
