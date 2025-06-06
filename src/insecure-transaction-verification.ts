/**
 * Insecure implementation of transaction data integrity verification
 * 
 * Security issues:
 * - Insufficient validation of transaction inputs
 * - Non-deterministic transaction serialization
 * - Weak hashing for transaction IDs
 * - Interprocedural weakness where validation failures affect signing
 */

import * as crypto from 'crypto';
import { Transaction, SignedTransaction } from './types/common';

// Function 1: Create a transaction hash (INSECURE)
export function createTransactionHashInsecure(transaction: Transaction): string {
  // VULNERABILITY: No validation of transaction structure
  
  // VULNERABILITY: Non-deterministic serialization
  // Using JSON.stringify without sorting keys can lead to different hashes
  // for the same logical transaction
  const txStr = JSON.stringify(transaction);
  
  // VULNERABILITY: Using a weak hashing algorithm
  return crypto.createHash('md5').update(txStr).digest('hex');
}

// Function 2: Minimal transaction validation (INSECURE)
export function validateTransactionMinimal(transaction: Transaction): boolean {
  // VULNERABILITY: Insufficient validation
  
  // Only check if transaction exists and has inputs and outputs
  if (!transaction || !transaction.inputs || !transaction.outputs) {
    return false;
  }
  
  // VULNERABILITY: No validation of input or output structure
  
  return true;
}

// Function 3: Sign transaction (INSECURE)
export function signTransactionInsecure(
  transaction: Transaction, 
  privateKey: string
): SignedTransaction | null {
  // VULNERABILITY: Minimal validation
  if (!validateTransactionMinimal(transaction)) {
    // VULNERABILITY: Returning null instead of throwing an error
    // can lead to silent failures
    return null;
  }
  
  // VULNERABILITY: Using weak hash
  const txHash = createTransactionHashInsecure(transaction);
  
  // Sign transaction
  const sign = crypto.createSign('SHA256');
  sign.update(txHash);
  const signature = sign.sign(privateKey, 'hex');
  
  // VULNERABILITY: Returning modifiable transaction object
  return {
    transaction: transaction, // Original, mutable object
    signature,
    txid: txHash
  };
}

// Function 4: Process transaction (INSECURE)
export function processTransactionInsecure(
  signedTx: SignedTransaction, 
  publicKey: string | Buffer
): { valid: boolean; transaction?: Transaction } {
  // VULNERABILITY: No validation that the transaction matches the txid
  
  // VULNERABILITY: No deep copy of the transaction object
  // This allows the transaction to be modified after validation
  const transaction = signedTx.transaction;
  const signature = signedTx.signature;
  const txid = signedTx.txid;
  
  // VULNERABILITY: Recreating the hash without ensuring it matches the provided txid
  const calculatedHash = createTransactionHashInsecure(transaction);
  
  // VULNERABILITY: Not comparing the calculated hash with the provided txid
  // This would allow transaction tampering
  
  // Verify signature
  const verify = crypto.createVerify('SHA256');
  verify.update(calculatedHash); // Using the recalculated hash
  
  if (!verify.verify(publicKey, Buffer.from(signature, 'hex'))) {
    return { valid: false };
  }
  
  // VULNERABILITY: Not checking if inputs are valid or already spent
  
  return { valid: true, transaction };
}

// Main function for insecure transaction handling
export function insecureTransactionHandling(
  transaction: Transaction, 
  privateKey: string
): SignedTransaction | null {
  // Sign transaction with minimal validation
  return signTransactionInsecure(transaction, privateKey);
}