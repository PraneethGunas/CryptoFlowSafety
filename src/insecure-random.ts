/**
 * Insecure implementation of random number generation for cryptographic purposes
 * 
 * Security issues:
 * - Uses non-cryptographic random number generation
 * - Insufficient entropy sources
 * - Predictable outputs
 * - Interprocedural weakness where insecure randomness affects crypto operations
 */

import * as crypto from 'crypto';
import { InsecureRandomResult } from './types/common';

// Function 1: Generate an insecure random number (INSECURE)
export function generateInsecureRandomNumber(min: number, max: number): number {
  // VULNERABILITY: Using Math.random() which is not cryptographically secure
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Function 2: Generate an insecure random buffer (INSECURE)
export function generateInsecureRandomBuffer(size: number): Buffer {
  // VULNERABILITY: Using Math.random() for generating random bytes
  const buffer = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    buffer[i] = Math.floor(Math.random() * 256);
  }
  return buffer;
}

// Global variable for "entropy" (INSECURE)
let globalCounter = Date.now();

// Function 3: Generate a pseudo-random string with time-based seed (INSECURE)
export function generatePseudoRandomString(
  length: number, 
  charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string {
  // VULNERABILITY: Using predictable entropy source
  // Using time-based seed and global counter
  const seed = Date.now() + globalCounter++;
  
  // VULNERABILITY: Linear congruential generator with known parameters
  // These are the parameters from Java's LCG
  const a = 25214903917;
  const c = 11;
  const m = 2**48;
  
  // Custom pseudo-random number generator
  let state = seed;
  const random = (): number => {
    state = (a * state + c) % m;
    return state / m;
  };
  
  // Generate the string
  let result = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(random() * charset.length);
    result += charset[randomIndex];
  }
  
  return result;
}

// Function 4: Use insecure random for cryptographic operations (INSECURE)
export function generateInsecureKey(type: string = 'AES-256'): Buffer {
  let keyLength: number;
  
  // Determine key length based on algorithm
  switch (type) {
    case 'AES-128':
      keyLength = 16;
      break;
    case 'AES-192':
      keyLength = 24;
      break;
    case 'AES-256':
      keyLength = 32;
      break;
    case 'HMAC-SHA256':
      keyLength = 32;
      break;
    default:
      throw new Error(`Unsupported key type: ${type}`);
  }
  
  // VULNERABILITY: Using insecure random generation for crypto keys
  return generateInsecureRandomBuffer(keyLength);
}

interface EncryptionResult {
  encrypted: string;
  key: string;
  iv: string;
}

// Function 5: Encrypt data with insecure key (INSECURE)
export function encryptWithInsecureKey(data: string, type: string = 'AES-256'): EncryptionResult {
  // Get an insecure key
  const key = generateInsecureKey(type);
  
  // VULNERABILITY: Using insecure IV generation
  const iv = generateInsecureRandomBuffer(16);
  
  // Mock encryption (in a real scenario, this would use a proper encryption algorithm)
  const mockEncrypted = Buffer.concat([
    Buffer.from('ENCRYPTED:'),
    key,
    iv,
    Buffer.from(data)
  ]);
  
  return {
    encrypted: mockEncrypted.toString('hex'),
    key: key.toString('hex'),
    iv: iv.toString('hex')
  };
}

// Main function demonstrating insecure random generation
export function insecureRandomOperations(data: string): InsecureRandomResult {
  // Generate an insecure random number between 1 and 100
  const randomNumber = generateInsecureRandomNumber(1, 100);
  
  // Generate an insecure random string of length 16
  const randomString = generatePseudoRandomString(16);
  
  // Encrypt data with an insecure key
  const encrypted = encryptWithInsecureKey(data);
  
  return {
    randomNumber,
    randomString,
    encrypted
  };
}