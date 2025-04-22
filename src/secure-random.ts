/**
 * Secure implementation of random number generation for cryptographic purposes
 * 
 * Key security features:
 * - Uses cryptographically secure random number generation
 * - Properly handles entropy
 * - Uses appropriate algorithms
 */

import * as crypto from 'crypto';
import { SecureRandomResult } from './types/common';

// Function 1: Generate a secure random number
export function generateSecureRandomNumber(min: number, max: number): number {
  if (min >= max) {
    throw new Error('Min must be less than max');
  }
  
  // Calculate the range
  const range = max - min + 1;
  
  // Calculate number of bytes needed
  const bitsNeeded = Math.ceil(Math.log2(range));
  const bytesNeeded = Math.ceil(bitsNeeded / 8);
  
  // Calculate the maximum value that ensures an unbiased distribution
  const max_value = Math.pow(2, bytesNeeded * 8) - (Math.pow(2, bytesNeeded * 8) % range);
  
  // Generate random bytes
  let randomBytes: Buffer;
  let randomValue: number;
  
  // Loop until we get a value within the acceptable range
  do {
    randomBytes = crypto.randomBytes(bytesNeeded);
    randomValue = 0;
    
    // Convert bytes to a number
    for (let i = 0; i < bytesNeeded; i++) {
      randomValue = (randomValue << 8) + randomBytes[i];
    }
  } while (randomValue >= max_value);
  
  // Calculate the result within our range
  return min + (randomValue % range);
}

// Function 2: Generate a secure random buffer
export function generateSecureRandomBuffer(size: number): Buffer {
  return crypto.randomBytes(size);
}

// Function 3: Generate a secure random string
export function generateSecureRandomString(
  length: number, 
  charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string {
  // Validate inputs
  if (length <= 0) {
    throw new Error('Length must be greater than 0');
  }
  
  if (charset.length < 2) {
    throw new Error('Charset must contain at least 2 characters');
  }
  
  // Prepare result string
  let result = '';
  
  // Generate random indices into the charset
  for (let i = 0; i < length; i++) {
    const randomIndex = generateSecureRandomNumber(0, charset.length - 1);
    result += charset[randomIndex];
  }
  
  return result;
}

// Function 4: Use secure random for cryptographic operations
export function generateSecureKey(type: string = 'AES-256'): Buffer {
  let keyLength: number;
  
  // Determine key length based on algorithm
  switch (type) {
    case 'AES-128':
      keyLength = 16; // 128 bits = 16 bytes
      break;
    case 'AES-192':
      keyLength = 24; // 192 bits = 24 bytes
      break;
    case 'AES-256':
      keyLength = 32; // 256 bits = 32 bytes
      break;
    case 'HMAC-SHA256':
      keyLength = 32; // 256 bits = 32 bytes
      break;
    default:
      throw new Error(`Unsupported key type: ${type}`);
  }
  
  // Generate secure random bytes for the key
  return generateSecureRandomBuffer(keyLength);
}

// Main function to demonstrate secure random generation
export function secureRandomOperations(): SecureRandomResult {
  // Generate a secure random number between 1 and 100
  const randomNumber = generateSecureRandomNumber(1, 100);
  
  // Generate a secure random string of length 16
  const randomString = generateSecureRandomString(16);
  
  // Generate a secure key for AES-256
  const key = generateSecureKey('AES-256');
  
  return {
    randomNumber,
    randomString,
    key: key.toString('hex')
  };
}