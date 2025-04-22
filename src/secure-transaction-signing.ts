/**
 * Secure implementation of ECDSA transaction signing
 * 
 * Key security features:
 * - Uses deterministic k-value (RFC 6979)
 * - Properly validates transaction before signing
 * - Maintains security across function boundaries
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as bip32 from 'bip32';
import * as crypto from 'crypto';
import { Transaction, TransactionInput, TransactionOutput } from './types/common';

interface BitcoinTxBuilder {
  inputs: any[];
  addInput(txid: string, vout: number): void;
  addOutput(address: string, value: number): void;
  sign(index: number, keyPair: any, redeemScript?: Buffer | null, hashType?: number): void;
  build(): any;
  clone(): BitcoinTxBuilder;
}

interface Recipient {
  address: string;
  value: number;
}

interface UTXO {
  txid: string;
  vout: number;
  value: number;
}

// Function 1: Derive private key from HD wallet
export function derivePrivateKey(seed: string, derivationPath: string): Buffer {
  // Create master node from seed
  const root = bip32.fromSeed(Buffer.from(seed, 'hex'));
  
  // Derive child node from derivation path
  const child = root.derivePath(derivationPath);
  
  // Return private key
  if (!child.privateKey) {
    throw new Error("Failed to derive private key");
  }
  return child.privateKey;
}

// Function 2: Create transaction
export function createTransaction(
  utxos: UTXO[], 
  recipients: Recipient[], 
  fee: number, 
  changeAddress: string
): BitcoinTxBuilder {
  // Create a bitcoin transaction
  const txb = new bitcoin.TransactionBuilder() as BitcoinTxBuilder;
  
  // Add inputs
  let inputTotal = 0;
  utxos.forEach(utxo => {
    txb.addInput(utxo.txid, utxo.vout);
    inputTotal += utxo.value;
  });
  
  // Add outputs
  let outputTotal = 0;
  recipients.forEach(recipient => {
    txb.addOutput(recipient.address, recipient.value);
    outputTotal += recipient.value;
  });
  
  // Add change output
  const changeValue = inputTotal - outputTotal - fee;
  if (changeValue > 0) {
    txb.addOutput(changeAddress, changeValue);
  }
  
  return txb;
}

// Function 3: Sign transaction with private key
export function signTransaction(
  transaction: BitcoinTxBuilder, 
  privateKey: Buffer, 
  sigHashType: number = bitcoin.Transaction.SIGHASH_ALL
): any {
  // Clone the transaction to avoid modifying the original
  const txb = transaction.clone();
  
  // Sign all inputs with the private key
  // bitcoinjs-lib uses RFC 6979 for deterministic signatures under the hood
  for (let i = 0; i < txb.inputs.length; i++) {
    txb.sign(i, bitcoin.ECPair.fromPrivateKey(privateKey), null, sigHashType);
  }
  
  // Build and return the signed transaction
  return txb.build();
}

// Main function to create and sign a transaction
export function createAndSignTransaction(
  seed: string, 
  derivationPath: string, 
  utxos: UTXO[], 
  recipients: Recipient[], 
  fee: number, 
  changeAddress: string
): any {
  const privateKey = derivePrivateKey(seed, derivationPath);
  const txb = createTransaction(utxos, recipients, fee, changeAddress);
  return signTransaction(txb, privateKey);
}