/**
 * Secure implementation of private key storage in a browser extension
 * 
 * Key security features:
 * - Uses the browser's secure storage API
 * - Encrypts data before storage
 * - Properly separates sensitive data across component boundaries
 */

// Note: This is a browser-extension specific implementation that uses
// Chrome extension APIs. These would not work in a standard Node.js environment.

import { ExtendedWindow, KeyData, StoredKeystore } from './types/browser';

// Declare global window type
declare const window: ExtendedWindow;
declare const chrome: any;
declare const crypto: Crypto;

// Function 1: Initialize secure storage
export async function initSecureStorage(password: string): Promise<CryptoKey> {
  // Generate a strong encryption key from the password
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  // Use Web Crypto API to derive a key
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    passwordData,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  
  // Derive an AES-GCM key
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  
  // Store the salt in local storage (salt is not sensitive)
  await chrome.storage.local.set({ salt: Array.from(salt) });
  
  // Return the encryption key (kept in memory, not stored)
  return encryptionKey;
}

// Function 2: Encrypt private key
export async function encryptPrivateKey(
  privateKey: string | Uint8Array, 
  encryptionKey: CryptoKey
): Promise<KeyData> {
  // Generate a random IV for AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Convert private key to buffer if it's a string
  const privateKeyBuffer = typeof privateKey === 'string' 
    ? new TextEncoder().encode(privateKey)
    : privateKey;
  
  // Encrypt the private key
  const encryptedData = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    encryptionKey,
    privateKeyBuffer
  );
  
  // Return the encrypted data and IV
  return {
    encrypted: Array.from(new Uint8Array(encryptedData)),
    iv: Array.from(iv)
  };
}

// Function 3: Store encrypted private key
export async function storeEncryptedKey(keyData: KeyData, keyName: string): Promise<void> {
  // Store the encrypted key in chrome.storage.local
  await chrome.storage.local.set({ 
    [keyName]: {
      encrypted: keyData.encrypted,
      iv: keyData.iv,
      timestamp: Date.now()
    }
  });
}

// Function 4: Retrieve and decrypt private key
export async function retrieveAndDecryptKey(
  keyName: string, 
  encryptionKey: CryptoKey
): Promise<Uint8Array> {
  // Get the encrypted key data from storage
  const data = await chrome.storage.local.get(keyName);
  if (!data[keyName]) {
    throw new Error(`No key found with name: ${keyName}`);
  }
  
  const keyData = data[keyName];
  
  // Decrypt the private key
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(keyData.iv)
    },
    encryptionKey,
    new Uint8Array(keyData.encrypted)
  );
  
  // Return the decrypted private key
  return new Uint8Array(decrypted);
}

interface SignedTransaction {
  transaction: any;
  signature: string;
}

// Function to sign a transaction with a key (helper function)
export function signTransactionWithKey(
  transaction: any, 
  privateKey: Uint8Array
): SignedTransaction {
  // This would be a real signing implementation
  // For this example, we're just creating a mock signature
  return {
    transaction,
    signature: `signed-with-private-key-${privateKey.slice(0, 8)}...`
  };
}

// Main function to store a private key securely
export async function secureStorePrivateKey(
  privateKey: string | Uint8Array, 
  password: string, 
  keyName: string
): Promise<void> {
  const encryptionKey = await initSecureStorage(password);
  const encryptedKey = await encryptPrivateKey(privateKey, encryptionKey);
  await storeEncryptedKey(encryptedKey, keyName);
}

// Function to retrieve a private key securely
export async function secureRetrievePrivateKey(
  password: string, 
  keyName: string
): Promise<Uint8Array> {
  // Recreate the encryption key from the password
  const salt = await chrome.storage.local.get('salt');
  if (!salt.salt) {
    throw new Error('No salt found in storage');
  }
  
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    passwordData,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(salt.salt),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  
  // Retrieve and decrypt the key
  return retrieveAndDecryptKey(keyName, encryptionKey);
}

interface TransactionMessage {
  action: string;
  password: string;
  keyName: string;
  transaction: any;
}

interface TransactionResponse {
  signedTransaction?: SignedTransaction;
  error?: string;
}

// Example message handler for background script
export function setupMessageHandling(): void {
  chrome.runtime.onMessage.addListener((
    message: TransactionMessage,
    sender: any,
    sendResponse: (response: TransactionResponse) => void
  ) => {
    if (message.action === 'signTransaction') {
      // Only receive the transaction data, not private keys
      // Private key is retrieved securely in the background
      secureRetrievePrivateKey(message.password, message.keyName)
        .then(privateKey => {
          // Sign transaction in the background script
          // This keeps the private key within the background context
          const signedTx = signTransactionWithKey(message.transaction, privateKey);
          // Return only the signed transaction
          sendResponse({ signedTransaction: signedTx });
        })
        .catch(error => {
          sendResponse({ error: error.message });
        });
      
      return true; // Keep the message channel open for async response
    }
  });
}