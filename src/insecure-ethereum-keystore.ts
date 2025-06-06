/**
 * Insecure implementation of Ethereum private key management
 * 
 * Security issues:
 * - Weak encryption of private keys
 * - Poor password-based key derivation
 * - Insecure memory handling
 * - Interprocedural weakness where key material is mishandled across functions
 */

import * as crypto from 'crypto';
import { InsecureKeyStore, EthereumKeyResult } from './types/common';

// Function 1: Generate an Ethereum key (INSECURE)
export function generateInsecureEthereumKey(): string {
  // VULNERABILITY: Using Math.random for key generation
  // This is not cryptographically secure
  const privateKey = Buffer.alloc(32);
  for (let i = 0; i < privateKey.length; i++) {
    privateKey[i] = Math.floor(Math.random() * 256);
  }
  
  return privateKey.toString('hex');
}

// Function 2: Encrypt a private key with a password (INSECURE)
export function encryptPrivateKeyInsecure(privateKey: string | Buffer, password: string): InsecureKeyStore {
  // Ensure privateKey is a Buffer
  const privateKeyBuffer = typeof privateKey === 'string' 
    ? Buffer.from(privateKey, 'hex') 
    : privateKey;
  
  // VULNERABILITY: Using a static salt
  const salt = Buffer.from('0123456789abcdef0123456789abcdef');
  
  // VULNERABILITY: Weak key derivation
  // Using a simple hash instead of a proper KDF
  const encryptionKey = crypto.createHash('sha256')
    .update(password + salt.toString('hex'))
    .digest();
  
  // VULNERABILITY: Using a static IV
  const iv = Buffer.from('00000000000000000000000000000000', 'hex');
  
  // Encrypt the private key
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(privateKeyBuffer),
    cipher.final()
  ]);
  
  // VULNERABILITY: No MAC to verify password correctness
  
  // Create the keystore object
  const keystore: InsecureKeyStore = {
    version: 1, // Non-standard version
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    salt: salt.toString('hex')
  };
  
  return keystore;
}

// Function 3: Decrypt a private key from a keystore (INSECURE)
export function decryptPrivateKeyInsecure(keystore: InsecureKeyStore, password: string): string | null {
  // VULNERABILITY: No validation of keystore format
  
  // VULNERABILITY: Weak key derivation
  const encryptionKey = crypto.createHash('sha256')
    .update(password + keystore.salt)
    .digest();
  
  // VULNERABILITY: No MAC verification
  // This means a wrong password will produce garbage without error
  
  // Decrypt the private key
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      encryptionKey,
      Buffer.from(keystore.iv, 'hex')
    );
    
    const privateKey = Buffer.concat([
      decipher.update(Buffer.from(keystore.ciphertext, 'hex')),
      decipher.final()
    ]);
    
    return privateKey.toString('hex');
  } catch (error) {
    // VULNERABILITY: Returning null instead of throwing an error
    // can lead to silent failures
    console.error(`Decryption error: ${(error as Error).message}`);
    return null;
  }
}

// Global variable to store private keys (INSECURE)
const privateKeyCache = new Map<string, string>();

// Function 4: Use private key with caching (INSECURE)
export function usePrivateKeyWithCaching<T>(
  keystoreId: string, 
  privateKey: string, 
  action: (key: string) => T
): T {
  // VULNERABILITY: Storing private keys in a global cache
  privateKeyCache.set(keystoreId, privateKey);
  
  try {
    // Perform the action with the private key
    return action(privateKey);
  } finally {
    // VULNERABILITY: Not removing the private key from the cache
    // This leaves it in memory indefinitely
  }
}

// Main function for insecure Ethereum key management
export function insecureEthereumKeyManagement(password: string): EthereumKeyResult {
  // Generate a new private key
  const privateKey = generateInsecureEthereumKey();
  
  // Encrypt the private key
  const keystore = encryptPrivateKeyInsecure(privateKey, password);
  const keystoreId = Math.random().toString(36).substring(2, 15);
  
  // VULNERABILITY: Using the private key with insecure caching
  const result = usePrivateKeyWithCaching(keystoreId, privateKey, (key) => {
    // Mock action that uses the private key
    return `Action performed with key ending in ...${key.slice(-4)}`;
  });
  
  return {
    keystoreId,
    keystore,
    result
  };
}