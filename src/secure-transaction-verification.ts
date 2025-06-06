/**
 * Secure implementation of transaction data integrity verification
 * 
 * Key security features:
 * - Properly validates transaction inputs
 * - Uses strong hashing for transaction IDs
 * - Validates transaction structure before signing
 */

import * as crypto from 'crypto';
import { Transaction, SignedTransaction } from './types/common';

// Function 1: Create a transaction hash
export function createTransactionHash(transaction: Transaction): string {
  // Validate transaction structure
  validateTransactionStructure(transaction);
  
  // Create a deterministic representation of the transaction
  const txStr = JSON.stringify(sortObject(transaction));
  
  // Hash the transaction
  return crypto.createHash('sha256').update(txStr).digest('hex');
}

// Function 2: Validate transaction structure
export function validateTransactionStructure(transaction: Transaction): boolean {
  // Check if transaction has required fields
  if (!transaction || typeof transaction !== 'object') {
    throw new Error('Transaction must be an object');
  }
  
  // Validate inputs
  if (!Array.isArray(transaction.inputs) || transaction.inputs.length === 0) {
    throw new Error('Transaction must have at least one input');
  }
  
  // Validate outputs
  if (!Array.isArray(transaction.outputs) || transaction.outputs.length === 0) {
    throw new Error('Transaction must have at least one output');
  }
  
  // Validate each input
  transaction.inputs.forEach((input, index) => {
    if (!input.txid || typeof input.txid !== 'string') {
      throw new Error(`Input ${index} must have a valid txid`);
    }
    if (typeof input.vout !== 'number' || input.vout < 0) {
      throw new Error(`Input ${index} must have a valid vout`);
    }
  });
  
  // Validate each output
  transaction.outputs.forEach((output, index) => {
    if (!output.address || typeof output.address !== 'string') {
      throw new Error(`Output ${index} must have a valid address`);
    }
    if (typeof output.value !== 'number' || output.value <= 0) {
      throw new Error(`Output ${index} must have a positive value`);
    }
  });
  
  return true;
}

// Function 3: Sort object properties for deterministic serialization
export function sortObject(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  // Arrays are kept in order, but their contents are sorted
  if (Array.isArray(obj)) {
    return obj.map(sortObject);
  }
  
  // Create a new object with sorted keys
  const sorted: Record<string, any> = {};
  Object.keys(obj).sort().forEach(key => {
    sorted[key] = sortObject(obj[key]);
  });
  
  return sorted;
}

// Function 4: Verify transaction signature
export function verifyTransactionSignature(
  transaction: Transaction, 
  signature: string, 
  publicKey: string | Buffer
): boolean {
  // Get the transaction hash
  const txHash = createTransactionHash(transaction);
  
  // Verify the signature
  const verify = crypto.createVerify('SHA256');
  verify.update(txHash);
  
  return verify.verify(publicKey, Buffer.from(signature, 'hex'));
}

// Main function to create and verify a transaction
export function secureTransactionHandling(
  transaction: Transaction, 
  privateKey: string | Buffer
): SignedTransaction {
  // Validate transaction structure
  validateTransactionStructure(transaction);
  
  // Create transaction hash
  const txHash = createTransactionHash(transaction);
  
  // Sign transaction
  const sign = crypto.createSign('SHA256');
  sign.update(txHash);
  const signature = sign.sign(privateKey, 'hex');
  
  // Return the signed transaction
  return {
    transaction,
    signature,
    txid: txHash
  };
}