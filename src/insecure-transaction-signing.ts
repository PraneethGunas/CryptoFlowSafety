/**
 * Insecure implementation of ECDSA transaction signing
 * 
 * Security issues:
 * - Uses custom implementation with non-deterministic k-value
 * - Non-deterministic k-value can lead to private key leakage if reused
 * - Interprocedural weakness where nonce generation affects signing security
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as bip32 from 'bip32';
import * as crypto from 'crypto';
import * as ecc from 'tiny-secp256k1';
import { Transaction } from './types/common';

interface BitcoinTxBuilder {
  inputs: any[];
  getHashForSignature(index: number, prevOutScript: Buffer, hashType: number): Buffer;
  addInput(txid: string, vout: number): void;
  addOutput(address: string, value: number): void;
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
export function derivePrivateKeyInsecure(seed: string, derivationPath: string): Buffer {
  // This part is implemented correctly
  const root = bip32.fromSeed(Buffer.from(seed, 'hex'));
  const child = root.derivePath(derivationPath);
  if (!child.privateKey) {
    throw new Error("Failed to derive private key");
  }
  return child.privateKey;
}

// Function 2: Create transaction
export function createTransactionInsecure(
  utxos: UTXO[], 
  recipients: Recipient[], 
  fee: number, 
  changeAddress: string
): BitcoinTxBuilder {
  // This part is implemented correctly
  const txb = new bitcoin.TransactionBuilder() as BitcoinTxBuilder;
  
  let inputTotal = 0;
  utxos.forEach(utxo => {
    txb.addInput(utxo.txid, utxo.vout);
    inputTotal += utxo.value;
  });
  
  let outputTotal = 0;
  recipients.forEach(recipient => {
    txb.addOutput(recipient.address, recipient.value);
    outputTotal += recipient.value;
  });
  
  const changeValue = inputTotal - outputTotal - fee;
  if (changeValue > 0) {
    txb.addOutput(changeAddress, changeValue);
  }
  
  return txb;
}

// Function 3: Generate nonce (k-value) for ECDSA signature - INSECURE
export function generateInsecureNonce(): Buffer {
  // VULNERABILITY: Using random instead of deterministic nonce generation
  // This can lead to nonce reuse or weak nonces, exposing the private key
  return crypto.randomBytes(32);
}

// Function 4: Sign transaction with private key and custom nonce
export function signTransactionInsecure(transaction: BitcoinTxBuilder, privateKey: Buffer): any {
  // Clone the transaction
  const txb = transaction.clone();
  
  // For each input, manually sign with a custom (insecure) nonce
  for (let i = 0; i < txb.inputs.length; i++) {
    // Get the hash to sign
    const hashToSign = txb.getHashForSignature(i, Buffer.alloc(32), bitcoin.Transaction.SIGHASH_ALL);
    
    // VULNERABILITY: Using custom signing with non-deterministic nonce
    // Bypassing the library's built-in RFC 6979 implementation
    const nonce = generateInsecureNonce();
    
    // Custom signature creation
    const sigObj = ecc.sign(hashToSign, privateKey, nonce);
    const signature = Buffer.concat([sigObj.signature, Buffer.from([bitcoin.Transaction.SIGHASH_ALL])]);
    
    // Apply the signature
    // Note: This is a simplified version for demonstration
    // In a real implementation, we would need to handle script types correctly
    txb.inputs[i].scriptSig = bitcoin.script.compile([signature, privateKey]);
  }
  
  return txb.build();
}

// Main function to create and sign a transaction
export function createAndSignTransactionInsecure(
  seed: string, 
  derivationPath: string, 
  utxos: UTXO[], 
  recipients: Recipient[], 
  fee: number, 
  changeAddress: string
): any {
  const privateKey = derivePrivateKeyInsecure(seed, derivationPath);
  const txb = createTransactionInsecure(utxos, recipients, fee, changeAddress);
  return signTransactionInsecure(txb, privateKey);
}