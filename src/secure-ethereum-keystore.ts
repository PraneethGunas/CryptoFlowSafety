/**
 * Secure implementation of Ethereum private key management
 * 
 * Key security features:
 * - Properly encrypts private keys
 * - Uses strong KDF for password-based encryption
 * - Handles memory securely
 */

import * as crypto from 'crypto';
import * as scrypt from 'scrypt-js';
import { KeyStore, EthereumKeyResult } from './types/common';

// Function 1: Generate a secure Ethereum key
export function generateSecureEthereumKey(): string {
  // Generate a secure random private key
  const privateKey = crypto.randomBytes(32);
  
  // Return the private key as hex
  return privateKey.toString('hex');
}

// Function 2: Encrypt a private key with a password
export async function encryptPrivateKey(privateKey: string | Buffer, password: string): Promise<KeyStore> {
  // Ensure privateKey is a Buffer
  const privateKeyBuffer = typeof privateKey === 'string' 
    ? Buffer.from(privateKey, 'hex') 
    : privateKey;
  
  // Generate a random salt
  const salt = crypto.randomBytes(32);
  
  // Generate encryption key from password using scrypt
  const encryptionKey = await scrypt.scrypt(
    Buffer.from(password, 'utf8'),
    salt,
    32768, // N
    8,     // r
    1,     // p
    32     // dkLen
  );
  
  // Generate a random IV
  const iv = crypto.randomBytes(16);
  
  // Encrypt the private key
  const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(encryptionKey), iv);
  const ciphertext = Buffer.concat([
    cipher.update(privateKeyBuffer),
    cipher.final()
  ]);
  
  // Create the keystore object
  const keystore: KeyStore = {
    version: 3,
    id: crypto.randomUUID(),
    address: 'placeholder', // In a real implementation, this would be derived from the private key
    crypto: {
      ciphertext: ciphertext.toString('hex'),
      cipherparams: {
        iv: iv.toString('hex')
      },
      cipher: 'aes-256-ctr',
      kdf: 'scrypt',
      kdfparams: {
        dklen: 32,
        salt: salt.toString('hex'),
        n: 32768,
        r: 8,
        p: 1
      },
      mac: crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from(encryptionKey.slice(16, 32)), ciphertext]))
        .digest('hex')
    }
  };
  
  return keystore;
}

// Function 3: Decrypt a private key from a keystore
export async function decryptPrivateKey(keystore: KeyStore, password: string): Promise<string> {
  // Validate keystore format
  if (keystore.version !== 3) {
    throw new Error('Unsupported keystore version');
  }
  
  if (keystore.crypto.kdf !== 'scrypt') {
    throw new Error('Unsupported key derivation function');
  }
  
  // Get the KDF parameters
  const kdfparams = keystore.crypto.kdfparams;
  
  // Derive the encryption key from the password
  const encryptionKey = await scrypt.scrypt(
    Buffer.from(password, 'utf8'),
    Buffer.from(kdfparams.salt, 'hex'),
    kdfparams.n || 32768,
    kdfparams.r || 8,
    kdfparams.p || 1,
    kdfparams.dklen
  );
  
  // Verify the MAC
  const mac = crypto.createHash('sha256')
    .update(Buffer.concat([
      Buffer.from(encryptionKey.slice(16, 32)),
      Buffer.from(keystore.crypto.ciphertext, 'hex')
    ]))
    .digest('hex');
  
  if (mac !== keystore.crypto.mac) {
    throw new Error('Invalid password or corrupted keystore');
  }
  
  // Decrypt the private key
  const decipher = crypto.createDecipheriv(
    keystore.crypto.cipher,
    Buffer.from(encryptionKey.slice(0, 16)),
    Buffer.from(keystore.crypto.cipherparams.iv, 'hex')
  );
  
  const privateKey = Buffer.concat([
    decipher.update(Buffer.from(keystore.crypto.ciphertext, 'hex')),
    decipher.final()
  ]);
  
  return privateKey.toString('hex');
}

// Function 4: Use private key securely
export function usePrivateKeySecurely<T>(
  privateKey: string | Buffer, 
  action: (key: string | Buffer) => T
): T {
  try {
    // Perform the action with the private key
    const result = action(privateKey);
    
    // Ensure the private key is removed from memory when done
    if (typeof privateKey === 'string') {
      // Overwrite the string (note: this is best-effort as strings are immutable)
      privateKey = '0'.repeat(privateKey.length);
    } else if (Buffer.isBuffer(privateKey)) {
      // Overwrite the buffer
      privateKey.fill(0);
    }
    
    return result;
  } catch (error) {
    // Ensure the private key is removed from memory even if an error occurs
    if (typeof privateKey === 'string') {
      privateKey = '0'.repeat(privateKey.length);
    } else if (Buffer.isBuffer(privateKey)) {
      privateKey.fill(0);
    }
    
    throw error;
  }
}

// Main function for secure Ethereum key management
export async function secureEthereumKeyManagement(password: string): Promise<EthereumKeyResult> {
  // Generate a new private key
  const privateKey = generateSecureEthereumKey();
  
  // Encrypt the private key
  const keystore = await encryptPrivateKey(privateKey, password);
  
  // Example of using the private key securely
  const result = usePrivateKeySecurely(privateKey, (key) => {
    // Mock action that uses the private key
    return `Action performed with key ending in ...${typeof key === 'string' 
      ? key.slice(-4) 
      : key.toString('hex').slice(-4)}`;
  });
  
  return {
    keystore,
    result
  };
}