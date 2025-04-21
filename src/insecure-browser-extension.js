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

// Function 1: Store private key (INSECURE)
function storePrivateKeyInsecure(privateKey, keyName) {
  // VULNERABILITY: Storing private key unencrypted in localStorage
  localStorage.setItem(keyName, privateKey);
}

// Function 2: Retrieve private key (INSECURE)
function retrievePrivateKeyInsecure(keyName) {
  // VULNERABILITY: Retrieving unencrypted private key from localStorage
  return localStorage.getItem(keyName);
}

// Function 3: Request transaction signing from background script (INSECURE)
function requestTransactionSigningInsecure(transaction, keyName) {
  // VULNERABILITY: Requesting private key from background script
  // and handling it in the content script (less secure context)
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { action: 'getPrivateKey', keyName },
      response => {
        if (response.error) {
          reject(new Error(response.error));
        } else {
          // VULNERABILITY: Private key is passed to content script
          const privateKey = response.privateKey;
          
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
function signTransactionLocally(transaction, privateKey) {
  // VULNERABILITY: Handling private key in page context
  // where it could be accessed by malicious scripts
  
  // Sign the transaction
  const txObj = JSON.parse(transaction);
  const signedTx = {
    ...txObj,
    signature: `signed_with_${privateKey.substring(0, 10)}...`
  };
  
  return JSON.stringify(signedTx);
}

// Example message handler for background script (INSECURE)
function setupInsecureMessageHandling() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getPrivateKey') {
      // VULNERABILITY: Sending private key through messaging
      const privateKey = retrievePrivateKeyInsecure(message.keyName);
      sendResponse({ privateKey });
    }
  });
}

// Main function to store and use a private key (INSECURE)
async function insecureHandlePrivateKey(privateKey, keyName, transaction) {
  // Store the key insecurely
  storePrivateKeyInsecure(privateKey, keyName);
  
  // Use the key insecurely
  return await requestTransactionSigningInsecure(transaction, keyName);
}

module.exports = {
  storePrivateKeyInsecure,
  retrievePrivateKeyInsecure,
  requestTransactionSigningInsecure,
  signTransactionLocally,
  setupInsecureMessageHandling,
  insecureHandlePrivateKey
};