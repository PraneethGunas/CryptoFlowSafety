/**
 * Insecure implementation of private key storage in a browser extension
 * 
 * Security issues:
 * - Stores keys unencrypted in localStorage
 * - Passes private keys between components through messaging
 * - No protection against XSS attacks accessing the storage
 * - Interprocedural weakness where sensitive data crosses boundaries insecurely
 */

// Note: This is a browser-extension specific implementation that uses
// browser APIs. These would not work in a standard Node.js environment.

import { ExtendedWindow } from './types/browser';

// Declare global window type
declare const window: ExtendedWindow;
declare const chrome: any;
declare const localStorage: Storage;

interface TransactionResponse {
  error?: string;
  privateKey?: string;
}

interface SignedTransaction {
  signature: string;
  [key: string]: any;
}

// Function 1: Store private key (INSECURE)
export function storePrivateKeyInsecure(privateKey: string, keyName: string): void {
  // VULNERABILITY: Storing private key unencrypted in localStorage
  localStorage.setItem(keyName, privateKey);
}

// Function 2: Retrieve private key (INSECURE)
export function retrievePrivateKeyInsecure(keyName: string): string | null {
  // VULNERABILITY: Retrieving unencrypted private key from localStorage
  return localStorage.getItem(keyName);
}

// Function 3: Request transaction signing from background script (INSECURE)
export function requestTransactionSigningInsecure(transaction: string, keyName: string): Promise<string> {
  // VULNERABILITY: Requesting private key from background script
  // and handling it in the content script (less secure context)
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { action: 'getPrivateKey', keyName },
      (response: TransactionResponse) => {
        if (response.error) {
          reject(new Error(response.error));
        } else {
          // VULNERABILITY: Private key is passed to content script
          const privateKey = response.privateKey as string;
          
          // Sign the transaction in the content script
          // This exposes the private key to the page context
          const signedTx = signTransactionLocally(transaction, privateKey);
          resolve(signedTx);
        }
      }
    );
  });
}

// Function 4: Handle transaction signing in page context (INSECURE)
export function signTransactionLocally(transaction: string, privateKey: string): string {
  // VULNERABILITY: Handling private key in page context
  // where it could be accessed by malicious scripts
  
  // Sign the transaction
  const txObj = JSON.parse(transaction);
  const signedTx: SignedTransaction = {
    ...txObj,
    signature: `signed_with_${privateKey.substring(0, 10)}...`
  };
  
  return JSON.stringify(signedTx);
}

// Example message handler for background script (INSECURE)
export function setupInsecureMessageHandling(): void {
  chrome.runtime.onMessage.addListener((
    message: { action: string; keyName: string },
    sender: any,
    sendResponse: (response: { privateKey?: string; error?: string }) => void
  ) => {
    if (message.action === 'getPrivateKey') {
      // VULNERABILITY: Sending private key through messaging
      const privateKey = retrievePrivateKeyInsecure(message.keyName);
      sendResponse({ privateKey: privateKey || undefined });
    }
  });
}

// Main function to store and use a private key (INSECURE)
export async function insecureHandlePrivateKey(
  privateKey: string,
  keyName: string,
  transaction: string
): Promise<string> {
  // Store the key insecurely
  storePrivateKeyInsecure(privateKey, keyName);
  
  // Use the key insecurely
  return await requestTransactionSigningInsecure(transaction, keyName);
}