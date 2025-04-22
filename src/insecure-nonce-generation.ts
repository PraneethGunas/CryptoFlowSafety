/**
 * Insecure implementation of nonce generation for ECDSA signatures
 * 
 * Security issues:
 * - Uses predictable/reused nonce for ECDSA
 * - Nonce reuse can lead to private key extraction
 * - Interprocedural weakness where nonce generation affects signing security
 */

import * as crypto from 'crypto';
import { Signature, BufferLike } from './types/common';

// Function 1: Generate an insecure nonce (INSECURE)
export function generateInsecureNonce(message: BufferLike): Buffer {
  // Ensure message is a Buffer
  const messageBuffer: Buffer = Buffer.isBuffer(message) 
    ? message as Buffer 
    : Buffer.from(typeof message === 'string' ? message : String(message), 'utf8');
  
  // VULNERABILITY: Using a predictable source for nonce generation
  // This can be predicted or may be reused, leading to key compromise
  
  // Using timestamp as part of the nonce (predictable)
  const timestamp = Date.now().toString();
  
  // Using message hash without additional entropy
  // This can lead to nonce reuse if the same message is signed twice
  const messageHash = crypto.createHash('sha256').update(messageBuffer).digest('hex');
  
  // VULNERABILITY: Creating a predictable nonce
  return crypto.createHash('sha256').update(timestamp + messageHash).digest();
}

// Global variable to store the last used nonce (INSECURE)
let lastNonce: Buffer | null = null;

// Function 2: Sign message with insecure nonce (INSECURE)
export function signWithInsecureNonce(privateKey: BufferLike, message: BufferLike): Signature {
  // Ensure privateKey is a Buffer
  const privateKeyBuffer: Buffer = Buffer.isBuffer(privateKey) 
    ? privateKey as Buffer 
    : Buffer.from(typeof privateKey === 'string' ? privateKey : String(privateKey), 'hex');
  
  // Ensure message is a Buffer
  const messageBuffer: Buffer = Buffer.isBuffer(message) 
    ? message as Buffer 
    : Buffer.from(typeof message === 'string' ? message : String(message), 'utf8');
  
  // Generate insecure nonce
  let nonce = generateInsecureNonce(messageBuffer);
  
  // VULNERABILITY: Sometimes reusing the last nonce (catastrophic)
  // This is an extreme vulnerability - reusing a nonce even once can leak the private key
  if (Math.random() < 0.1 && lastNonce) {
    // 10% chance to reuse the last nonce
    nonce = lastNonce;
  } else {
    lastNonce = nonce;
  }
  
  // Mock signing function - in real code, this would use the actual ECDSA algorithm
  const signature: Signature = {
    r: crypto.createHash('sha256').update(nonce).digest('hex'),
    s: crypto.createHash('sha256').update(Buffer.concat([nonce, privateKeyBuffer, messageBuffer])).digest('hex')
  };
  
  return signature;
}

// Function 3: Sign multiple messages (INSECURE)
export function signMultipleMessagesInsecure(privateKey: BufferLike, messages: BufferLike[]): Signature[] {
  // Ensure privateKey is a Buffer
  const privateKeyBuffer: Buffer = Buffer.isBuffer(privateKey) 
    ? privateKey as Buffer 
    : Buffer.from(typeof privateKey === 'string' ? privateKey : String(privateKey), 'hex');
  
  // VULNERABILITY: Using the same nonce for multiple messages
  // This is catastrophic - signing multiple messages with the same nonce
  // allows an attacker to extract the private key
  
  // Generate a single nonce for all messages
  const singleNonce = crypto.randomBytes(32);
  
  const signatures: Signature[] = [];
  for (let message of messages) {
    // Ensure message is a Buffer
    const messageBuffer: Buffer = Buffer.isBuffer(message) 
      ? message as Buffer 
      : Buffer.from(typeof message === 'string' ? message : String(message), 'utf8');
    
    // VULNERABILITY: Reusing the same nonce for different messages
    // Mock signing function
    const signature: Signature = {
      r: crypto.createHash('sha256').update(singleNonce).digest('hex'),
      s: crypto.createHash('sha256').update(Buffer.concat([singleNonce, privateKeyBuffer, messageBuffer])).digest('hex')
    };
    
    signatures.push(signature);
  }
  
  return signatures;
}

// Main function to sign messages insecurely
export function insecureSignMessages(privateKey: BufferLike, messages: BufferLike | BufferLike[]): Signature | Signature[] {
  if (Array.isArray(messages)) {
    return signMultipleMessagesInsecure(privateKey, messages);
  } else {
    return signWithInsecureNonce(privateKey, messages);
  }
}