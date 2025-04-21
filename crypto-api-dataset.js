/* 
 * DATASET: Interprocedural Cryptographic API Misuse
 * ================================================
 * 
 * This dataset contains examples of secure and insecure cryptographic API usage
 * across multiple functions, specifically focused on cryptocurrency operations.
 */

// =============================================================================
// EXAMPLE 1: HD WALLET SEED GENERATION - SECURE
// =============================================================================

/**
 * Secure implementation of HD wallet seed generation
 * 
 * Key security features:
 * - Uses crypto.getRandomValues for strong entropy
 * - Proper mnemonic generation using BIP39
 * - Functions are properly separated but maintain security across boundaries
 */

// File: secure-wallet-generation.js
const bip39 = require('bip39');
const crypto = require('crypto');

// Function 1: Generate secure entropy
function generateSecureEntropy(bits = 256) {
  // Use a cryptographically secure random number generator
  const buffer = crypto.randomBytes(bits / 8);
  return buffer;
}

// Function 2: Generate mnemonic from entropy
function generateMnemonic(entropy) {
  // Use BIP39 to convert entropy to mnemonic
  const mnemonic = bip39.entropyToMnemonic(entropy);
  return mnemonic;
}

// Function 3: Create seed from mnemonic
function createSeedFromMnemonic(mnemonic, passphrase = '') {
  // Generate seed using BIP39
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  return seed;
}

// Main wallet creation function
function createSecureWallet(passphrase = '') {
  const entropy = generateSecureEntropy(256);
  const mnemonic = generateMnemonic(entropy);
  const seed = createSeedFromMnemonic(mnemonic, passphrase);
  
  return {
    mnemonic,
    seed: seed.toString('hex')
  };
}

// =============================================================================
// EXAMPLE 2: HD WALLET SEED GENERATION - INSECURE
// =============================================================================

/**
 * Insecure implementation of HD wallet seed generation
 * 
 * Security issues:
 * - Uses Math.random() which is not cryptographically secure
 * - Weak entropy generation could lead to predictable wallets
 * - Seed can be potentially recovered by attackers
 * - Interprocedural weakness where weak entropy propagates across functions
 */

// File: insecure-wallet-generation.js
const bip39 = require('bip39');

// Function 1: Generate insecure entropy (INSECURE)
function generateWeakEntropy(bits = 256) {
  // VULNERABILITY: Using Math.random() for cryptographic purposes
  // Math.random() is not cryptographically secure and can be predicted
  const buffer = Buffer.alloc(bits / 8);
  for (let i = 0; i < buffer.length; i++) {
    // Scaled to 0-255 range for byte values
    buffer[i] = Math.floor(Math.random() * 256);
  }
  return buffer;
}

// Function 2: Generate mnemonic from entropy
function generateMnemonicInsecure(entropy) {
  // This function itself is implemented correctly
  // but it's receiving weak entropy from the caller
  const mnemonic = bip39.entropyToMnemonic(entropy);
  return mnemonic;
}

// Function 3: Create seed from mnemonic
function createSeedFromMnemonicInsecure(mnemonic, passphrase = '') {
  // This function is implemented correctly
  // but it's using a mnemonic generated from weak entropy
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  return seed;
}

// Main wallet creation function
function createInsecureWallet(passphrase = '') {
  // The entire wallet is compromised due to weak entropy generation
  // in the first function of this call chain
  const entropy = generateWeakEntropy(256);
  const mnemonic = generateMnemonicInsecure(entropy);
  const seed = createSeedFromMnemonicInsecure(mnemonic, passphrase);
  
  return {
    mnemonic,
    seed: seed.toString('hex')
  };
}

// =============================================================================
// EXAMPLE 3: TRANSACTION SIGNING WITH ECDSA - SECURE
// =============================================================================

/**
 * Secure implementation of ECDSA transaction signing
 * 
 * Key security features:
 * - Uses deterministic k-value (RFC 6979)
 * - Properly validates transaction before signing
 * - Maintains security across function boundaries
 */

// File: secure-transaction-signing.js
const bitcoin = require('bitcoinjs-lib');
const bip32 = require('bip32');
const crypto = require('crypto');

// Function 1: Derive private key from HD wallet
function derivePrivateKey(seed, derivationPath) {
  // Create master node from seed
  const root = bip32.fromSeed(Buffer.from(seed, 'hex'));
  
  // Derive child node from derivation path
  const child = root.derivePath(derivationPath);
  
  // Return private key
  return child.privateKey;
}

// Function 2: Create transaction
function createTransaction(utxos, recipients, fee, changeAddress) {
  // Create a bitcoin transaction
  const txb = new bitcoin.TransactionBuilder();
  
  // Add inputs
  let inputTotal = 0;
  utxos.forEach(utxo => {
    txb.addInput(utxo.txid, utxo.vout);
    inputTotal += utxo.value;
  });
  
  // Add outputs
  let outputTotal = 0;
  recipients.forEach(recipient => {
    txb.addOutput(recipient.address, recipient.value);
    outputTotal += recipient.value;
  });
  
  // Add change output
  const changeValue = inputTotal - outputTotal - fee;
  if (changeValue > 0) {
    txb.addOutput(changeAddress, changeValue);
  }
  
  return txb;
}

// Function 3: Sign transaction with private key
function signTransaction(transaction, privateKey, sigHashType = bitcoin.Transaction.SIGHASH_ALL) {
  // Clone the transaction to avoid modifying the original
  const txb = transaction.clone();
  
  // Sign all inputs with the private key
  // bitcoinjs-lib uses RFC 6979 for deterministic signatures under the hood
  for (let i = 0; i < txb.inputs.length; i++) {
    txb.sign(i, bitcoin.ECPair.fromPrivateKey(privateKey), null, sigHashType);
  }
  
  // Build and return the signed transaction
  return txb.build();
}

// Main function to create and sign a transaction
function createAndSignTransaction(seed, derivationPath, utxos, recipients, fee, changeAddress) {
  const privateKey = derivePrivateKey(seed, derivationPath);
  const txb = createTransaction(utxos, recipients, fee, changeAddress);
  return signTransaction(txb, privateKey);
}

// =============================================================================
// EXAMPLE 4: TRANSACTION SIGNING WITH ECDSA - INSECURE
// =============================================================================

/**
 * Insecure implementation of ECDSA transaction signing
 * 
 * Security issues:
 * - Uses custom implementation with non-deterministic k-value
 * - Non-deterministic k-value can lead to private key leakage if reused
 * - Interprocedural weakness where nonce generation affects signing security
 */

// File: insecure-transaction-signing.js
const bitcoin = require('bitcoinjs-lib');
const bip32 = require('bip32');
const crypto = require('crypto');
const ecc = require('tiny-secp256k1');

// Function 1: Derive private key from HD wallet
function derivePrivateKeyInsecure(seed, derivationPath) {
  // This part is implemented correctly
  const root = bip32.fromSeed(Buffer.from(seed, 'hex'));
  const child = root.derivePath(derivationPath);
  return child.privateKey;
}

// Function 2: Create transaction
function createTransactionInsecure(utxos, recipients, fee, changeAddress) {
  // This part is implemented correctly
  const txb = new bitcoin.TransactionBuilder();
  
  let inputTotal = 0;
  utxos.forEach(utxo => {
    txb.addInput(utxo.txid, utxo.vout);
    inputTotal += utxo.value;
  });
  
  let outputTotal = 0;
  recipients.forEach(recipient => {
    txb.addOutput(recipient.address, recipient.value);
    outputTotal += recipient.value;
  });
  
  const changeValue = inputTotal - outputTotal - fee;
  if (changeValue > 0) {
    txb.addOutput(changeAddress, changeValue);
  }
  
  return txb;
}

// Function 3: Generate nonce (k-value) for ECDSA signature - INSECURE
function generateInsecureNonce() {
  // VULNERABILITY: Using random instead of deterministic nonce generation
  // This can lead to nonce reuse or weak nonces, exposing the private key
  return crypto.randomBytes(32);
}

// Function 4: Sign transaction with private key and custom nonce
function signTransactionInsecure(transaction, privateKey) {
  // Clone the transaction
  const txb = transaction.clone();
  
  // For each input, manually sign with a custom (insecure) nonce
  for (let i = 0; i < txb.inputs.length; i++) {
    // Get the hash to sign
    const hashToSign = txb.getHashForSignature(i, Buffer.alloc(32), bitcoin.Transaction.SIGHASH_ALL);
    
    // VULNERABILITY: Using custom signing with non-deterministic nonce
    // Bypassing the library's built-in RFC 6979 implementation
    const nonce = generateInsecureNonce();
    
    // Custom signature creation
    const sigObj = ecc.sign(hashToSign, privateKey, nonce);
    const signature = Buffer.concat([sigObj.signature, Buffer.from([bitcoin.Transaction.SIGHASH_ALL])]);
    
    // Apply the signature
    txb.inputs[i].scriptSig = bitcoin.script.compile([signature, privateKey]);
  }
  
  return txb.build();
}

// Main function to create and sign a transaction
function createAndSignTransactionInsecure(seed, derivationPath, utxos, recipients, fee, changeAddress) {
  const privateKey = derivePrivateKeyInsecure(seed, derivationPath);
  const txb = createTransactionInsecure(utxos, recipients, fee, changeAddress);
  return signTransactionInsecure(txb, privateKey);
}

// =============================================================================
// EXAMPLE 5: KEY STORAGE IN BROWSER EXTENSION - SECURE
// =============================================================================

/**
 * Secure implementation of private key storage in a browser extension
 * 
 * Key security features:
 * - Uses the browser's secure storage API
 * - Encrypts data before storage
 * - Properly separates sensitive data across component boundaries
 */

// File: secure-browser-extension.js
// Background script (background.js)

// Function 1: Initialize secure storage
async function initSecureStorage(password) {
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
async function encryptPrivateKey(privateKey, encryptionKey) {
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
async function storeEncryptedKey(keyData, keyName) {
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
async function retrieveAndDecryptKey(keyName, encryptionKey) {
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

// Main function to store a private key securely
async function secureStorePrivateKey(privateKey, password, keyName) {
  const encryptionKey = await initSecureStorage(password);
  const encryptedKey = await encryptPrivateKey(privateKey, encryptionKey);
  await storeEncryptedKey(encryptedKey, keyName);
}

// Function to retrieve a private key securely
async function secureRetrievePrivateKey(password, keyName) {
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

// Message handling between extension components
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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

// =============================================================================
// EXAMPLE 6: KEY STORAGE IN BROWSER EXTENSION - INSECURE
// =============================================================================

/**
 * Insecure implementation of private key storage in a browser extension
 * 
 * Security issues:
 * - Stores keys unencrypted in localStorage
 * - Passes private keys between components through messaging
 * - No protection against XSS attacks accessing the storage
 * - Interprocedural weakness where sensitive data crosses boundaries insecurely
 */

// File: insecure-browser-extension.js
// Background script (background.js)

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

// Content script (content.js)
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

// Background script message handler (INSECURE)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getPrivateKey') {
    // VULNERABILITY: Sending private key through messaging
    const privateKey = retrievePrivateKeyInsecure(message.keyName);
    sendResponse({ privateKey });
  }
});

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

// Main function to store and use a private key (INSECURE)
async function insecureHandlePrivateKey(privateKey, keyName, transaction) {
  // Store the key insecurely
  storePrivateKeyInsecure(privateKey, keyName);
  
  // Use the key insecurely
  return await requestTransactionSigningInsecure(transaction, keyName);
}

// =============================================================================
// EXAMPLE 7: BIP32/39/44 DERIVATION PATH IMPLEMENTATION - SECURE
// =============================================================================

/**
 * Secure implementation of BIP32/39/44 for derivation path handling
 * 
 * Key security features:
 * - Properly validates derivation paths
 * - Uses hardened derivation for sensitive paths
 * - Prevents derivation from xpub when inappropriate
 */

// File: secure-derivation-path.js
const bip32 = require('bip32');
const bip39 = require('bip39');

// Function 1: Validate a derivation path
function validateDerivationPath(path) {
  // Check if the path starts with m/
  if (!path.startsWith('m/')) {
    throw new Error('Derivation path must start with "m/"');
  }
  
  // Split the path and validate each segment
  const segments = path.slice(2).split('/');
  
  for (const segment of segments) {
    // Check if segment has valid format
    const hasHardened = segment.endsWith("'") || segment.endsWith("h");
    const indexStr = hasHardened ? segment.slice(0, -1) : segment;
    const index = parseInt(indexStr, 10);
    
    // Validate the index
    if (isNaN(index) || index < 0 || index >= 0x80000000) {
      throw new Error(`Invalid index in derivation path: ${segment}`);
    }
  }
  
  return true;
}

// Function 2: Check if a path requires private key
function requiresPrivateKey(path) {
  // If any segment is hardened, private key is required
  const segments = path.slice(2).split('/');
  return segments.some(segment => 
    segment.endsWith("'") || segment.endsWith("h")
  );
}

// Function 3: Derive a node from seed and path
function deriveNodeFromSeed(seed, path) {
  // Validate the path first
  validateDerivationPath(path);
  
  // Create master node
  const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));
  
  // Derive child node
  return masterNode.derivePath(path);
}

// Function 4: Derive a node from xpub and path
function deriveNodeFromXpub(xpub, path) {
  // Validate the path
  validateDerivationPath(path);
  
  // Check if the path requires private key
  if (requiresPrivateKey(path)) {
    throw new Error('Cannot derive hardened path from xpub');
  }
  
  // Create node from xpub
  const parentNode = bip32.fromBase58(xpub);
  
  // Ensure that the parent node doesn't have a private key
  if (parentNode.privateKey) {
    throw new Error('Expected xpub, got xprv');
  }
  
  // Normalize path - remove m/ prefix if present
  const normalizedPath = path.startsWith('m/') ? path.slice(2) : path;
  
  // If path is empty, return the parent
  if (!normalizedPath) {
    return parentNode;
  }
  
  // Derive child node
  return parentNode.derivePath(normalizedPath);
}

// Main function to handle wallet derivation securely
function secureWalletDerivation(seedOrXpub, path, isSeed = true) {
  try {
    // Choose the appropriate derivation method
    if (isSeed) {
      return deriveNodeFromSeed(seedOrXpub, path);
    } else {
      return deriveNodeFromXpub(seedOrXpub, path);
    }
  } catch (error) {
    console.error(`Derivation error: ${error.message}`);
    return null;
  }
}

// =============================================================================
// EXAMPLE 8: BIP32/39/44 DERIVATION PATH IMPLEMENTATION - INSECURE
// =============================================================================

/**
 * Insecure implementation of BIP32/39/44 for derivation path handling
 * 
 * Security issues:
 * - No validation of derivation paths
 * - Attempts to derive hardened paths from xpub
 * - Doesn't enforce proper BIP44 structure
 * - Interprocedural weakness where validation failures propagate
 */

// File: insecure-derivation-path.js
const bip32 = require('bip32');
const bip39 = require('bip39');

// Function 1: Parse derivation path without validation (INSECURE)
function parseDerivationPathInsecure(path) {
  // VULNERABILITY: No validation of the path format
  // Simply removes the m/ prefix if present
  return path.startsWith('m/') ? path.slice(2) : path;
}

// Function 2: Derive a node from seed and path (INSECURE)
function deriveNodeFromSeedInsecure(seed, path) {
  // VULNERABILITY: No validation of the derivation path
  try {
    // Create master node
    const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));
    
    // Derive child node without validation
    return masterNode.derivePath(path);
  } catch (error) {
    // VULNERABILITY: Silently catching errors
    console.error(`Error: ${error.message}`);
    return null;
  }
}

// Function 3: Derive a node from xpub and path (INSECURE)
function deriveNodeFromXpubInsecure(xpub, path) {
  // VULNERABILITY: No check if the path requires private key
  try {
    // Create node from xpub
    const parentNode = bip32.fromBase58(xpub);
    
    // VULNERABILITY: No check for xprv vs xpub
    
    // Normalize path
    const normalizedPath = parseDerivationPathInsecure(path);
    
    // Derive child node
    // VULNERABILITY: Will fail on hardened paths but doesn't prevent the attempt
    return parentNode.derivePath(normalizedPath);
  } catch (error) {
    // VULNERABILITY: Silently catching errors
    console.error(`Error: ${error.message}`);
    return null;
  }
}

// Function 4: Generate addresses from a path (INSECURE)
function generateAddressesInsecure(seedOrXpub, startIndex, count, change = 0, isSeed = true) {
  // VULNERABILITY: Constructing a path without validation
  // and not enforcing BIP44 structure
  
  // Generate a custom path with potential issues
  let basePath = `m/44'/0'/${startIndex}'`;
  if (!isSeed) {
    // VULNERABILITY: Attempting to use hardened paths with xpub
    basePath = `${startIndex}'/0/0`;
  }
  
  // Get the base node
  const baseNode = isSeed 
    ? deriveNodeFromSeedInsecure(seedOrXpub, basePath)
    : deriveNodeFromXpubInsecure(seedOrXpub, basePath);
  
  if (!baseNode) {
    return [];
  }
  
  // Generate addresses
  const addresses = [];
  for (let i = 0; i < count; i++) {
    // VULNERABILITY: Using a non-standard path structure
    const path = `${change}/${i}`;
    try {
      const addressNode = baseNode.derivePath(path);
      addresses.push({
        path: `${basePath}/${path}`,
        address: addressNode.publicKey.toString('hex')
      });
    } catch (error) {
      // VULNERABILITY: Silently catching errors and continuing
      console.error(`Error generating address ${i}: ${error.message}`);
    }
  }
  
  return addresses;
}

// Main function to handle wallet derivation insecurely
function insecureWalletDerivation(seedOrXpub, startIndex = 0, count = 5, isSeed = true) {
  return generateAddressesInsecure(seedOrXpub, startIndex, count, 0, isSeed);
}

// =============================================================================
// EXAMPLE 9: NONCE GENERATION FOR ECDSA SIGNATURES - SECURE
// =============================================================================

/**
 * Secure implementation of nonce generation for ECDSA signatures
 * 
 * Key security features:
 * - Uses deterministic nonce generation (RFC 6979)
 * - Prevents nonce reuse
 * - Manages entropy properly
 */

// File: secure-nonce-generation.js
const crypto = require('crypto');
const createHmac = crypto.createHmac;

// Function 1: Generate a deterministic nonce (k-value) for ECDSA
function generateDeterministicNonce(privateKey, message, algorithm = 'sha256') {
  // Implementation of RFC 6979 for deterministic nonce generation
  // This prevents nonce reuse that could leak the private key
  
  if (!Buffer.isBuffer(privateKey)) {
    privateKey = Buffer.from(privateKey, 'hex');
  }
  
  if (!Buffer.isBuffer(message)) {
    message = Buffer.from(message, 'hex');
  }
  
  // Ensure the private key is the right length
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }
  
  // Step 1: Hash the message using the specified algorithm
  const h1 = crypto.createHash(algorithm).update(message).digest();
  
  // Step 2: Initialize variables
  let v = Buffer.alloc(32, 1); // Initial V = 1...1
  let k = Buffer.alloc(32, 0); // Initial K = 0...0
  
  // Step 3: K = HMAC_K(V || 0x00 || private_key || message_hash)
  let data = Buffer.concat([v, Buffer.from([0]), privateKey, h1]);
  k = createHmac(algorithm, k).update(data).digest();
  
  // Step 4: V = HMAC_K(V)
  v = createHmac(algorithm, k).update(v).digest();
  
  // Step 5: K = HMAC_K(V || 0x01 || private_key || message_hash)
  data = Buffer.concat([v, Buffer.from([1]), privateKey, h1]);
  k = createHmac(algorithm, k).update(data).digest();
  
  // Step 6: V = HMAC_K(V)
  v = createHmac(algorithm, k).update(v).digest();
  
  // Step 7: Generate a nonce
  v = createHmac(algorithm, k).update(v).digest();
  
  // Ensure the nonce is less than the curve order (n)
  // (Simplified - a full implementation would check against the actual curve order)
  return v;
}

// Function 2: Sign message with private key using deterministic nonce
function signWithDeterministicNonce(privateKey, message) {
  // Generate deterministic nonce
  const nonce = generateDeterministicNonce(privateKey, message);
  
  // In a real implementation, this would use the nonce with ECDSA
  // For this example, we're just showing the secure generation
  
  // Mock signing function - in real code, this would use the actual ECDSA algorithm
  const signature = {
    r: crypto.createHash('sha256').update(nonce).digest('hex'),
    s: crypto.createHash('sha256').update(Buffer.concat([nonce, privateKey, message])).digest('hex')
  };
  
  return signature;
}

// Function 3: Verify signature
function verifySignature(publicKey, message, signature) {
  // In a real implementation, this would verify the ECDSA signature
  // For this example, we're just showing the concept
  
  // Mock verification
  return true;
}

// Main function to sign a message
function secureSignMessage(privateKey, message) {
  // Sign the message with deterministic nonce
  return signWithDeterministicNonce(privateKey, message);
}

// =============================================================================
// EXAMPLE 10: NONCE GENERATION FOR ECDSA SIGNATURES - INSECURE
// =============================================================================

/**
 * Insecure implementation of nonce generation for ECDSA signatures
 * 
 * Security issues:
 * - Uses predictable/reused nonce for ECDSA
 * - Nonce reuse can lead to private key extraction
 * - Interprocedural weakness where nonce generation affects signing security
 */

// File: insecure-nonce-generation.js
const crypto = require('crypto');

// Function 1: Generate an insecure nonce (INSECURE)
function generateInsecureNonce(message) {
  // VULNERABILITY: Using a predictable source for nonce generation
  // This can be predicted or may be reused, leading to key compromise
  
  // Using timestamp as part of the nonce (predictable)
  const timestamp = Date.now().toString();
  
  // Using message hash without additional entropy
  // This can lead to nonce reuse if the same message is signed twice
  const messageHash = crypto.createHash('sha256').update(message).digest('hex');
  
  // VULNERABILITY: Creating a predictable nonce
  return crypto.createHash('sha256').update(timestamp + messageHash).digest();
}

// Global variable to store the last used nonce (INSECURE)
let lastNonce = null;

// Function 2: Sign message with insecure nonce (INSECURE)
function signWithInsecureNonce(privateKey, message) {
  // Generate insecure nonce
  let nonce = generateInsecureNonce(message);
  
  // VULNERABILITY: Sometimes reusing the last nonce (catastrophic)
  // This is an extreme vulnerability - reusing a nonce even once can leak the private key
  if (Math.random() < 0.1 && lastNonce) {
    // 10% chance to reuse the last nonce
    nonce = lastNonce;
  } else {
    lastNonce = nonce;
  }
  
  // Mock signing function - in real code, this would use the actual ECDSA algorithm
  const signature = {
    r: crypto.createHash('sha256').update(nonce).digest('hex'),
    s: crypto.createHash('sha256').update(Buffer.concat([nonce, privateKey, message])).digest('hex')
  };
  
  return signature;
}

// Function 3: Sign multiple messages (INSECURE)
function signMultipleMessagesInsecure(privateKey, messages) {
  // VULNERABILITY: Using the same nonce for multiple messages
  // This is catastrophic - signing multiple messages with the same nonce
  // allows an attacker to extract the private key
  
  // Generate a single nonce for all messages
  const singleNonce = crypto.randomBytes(32);
  
  const signatures = [];
  for (const message of messages) {
    // VULNERABILITY: Reusing the same nonce for different messages
    // Mock signing function
    const signature = {
      r: crypto.createHash('sha256').update(singleNonce).digest('hex'),
      s: crypto.createHash('sha256').update(Buffer.concat([singleNonce, privateKey, message])).digest('hex')
    };
    
    signatures.push(signature);
  }
  
  return signatures;
}

// Main function to sign messages insecurely
function insecureSignMessages(privateKey, messages) {
  if (Array.isArray(messages)) {
    return signMultipleMessagesInsecure(privateKey, messages);
  } else {
    return signWithInsecureNonce(privateKey, messages);
  }
}

// =============================================================================
// EXAMPLE 11: TRANSACTION DATA INTEGRITY - SECURE
// =============================================================================

/**
 * Secure implementation of transaction data integrity verification
 * 
 * Key security features:
 * - Properly validates transaction inputs
 * - Uses strong hashing for transaction IDs
 * - Validates transaction structure before signing
 */

// File: secure-transaction-verification.js
const crypto = require('crypto');

// Function 1: Create a transaction hash
function createTransactionHash(transaction) {
  // Validate transaction structure
  validateTransactionStructure(transaction);
  
  // Create a deterministic representation of the transaction
  const txStr = JSON.stringify(sortObject(transaction));
  
  // Hash the transaction
  return crypto.createHash('sha256').update(txStr).digest('hex');
}

// Function 2: Validate transaction structure
function validateTransactionStructure(transaction) {
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
function sortObject(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  // Arrays are kept in order, but their contents are sorted
  if (Array.isArray(obj)) {
    return obj.map(sortObject);
  }
  
  // Create a new object with sorted keys
  const sorted = {};
  Object.keys(obj).sort().forEach(key => {
    sorted[key] = sortObject(obj[key]);
  });
  
  return sorted;
}

// Function 4: Verify transaction signature
function verifyTransactionSignature(transaction, signature, publicKey) {
  // Get the transaction hash
  const txHash = createTransactionHash(transaction);
  
  // Verify the signature
  const verify = crypto.createVerify('SHA256');
  verify.update(txHash);
  
  return verify.verify(publicKey, Buffer.from(signature, 'hex'));
}

// Main function to create and verify a transaction
function secureTransactionHandling(transaction, privateKey) {
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

// =============================================================================
// EXAMPLE 12: TRANSACTION DATA INTEGRITY - INSECURE
// =============================================================================

/**
 * Insecure implementation of transaction data integrity verification
 * 
 * Security issues:
 * - Insufficient validation of transaction inputs
 * - Non-deterministic transaction serialization
 * - Weak hashing for transaction IDs
 * - Interprocedural weakness where validation failures affect signing
 */

// File: insecure-transaction-verification.js
const crypto = require('crypto');

// Function 1: Create a transaction hash (INSECURE)
function createTransactionHashInsecure(transaction) {
  // VULNERABILITY: No validation of transaction structure
  
  // VULNERABILITY: Non-deterministic serialization
  // Using JSON.stringify without sorting keys can lead to different hashes
  // for the same logical transaction
  const txStr = JSON.stringify(transaction);
  
  // VULNERABILITY: Using a weak hashing algorithm
  return crypto.createHash('md5').update(txStr).digest('hex');
}

// Function 2: Minimal transaction validation (INSECURE)
function validateTransactionMinimal(transaction) {
  // VULNERABILITY: Insufficient validation
  
  // Only check if transaction exists and has inputs and outputs
  if (!transaction || !transaction.inputs || !transaction.outputs) {
    return false;
  }
  
  // VULNERABILITY: No validation of input or output structure
  
  return true;
}

// Function 3: Sign transaction (INSECURE)
function signTransactionInsecure(transaction, privateKey) {
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
function processTransactionInsecure(signedTx, publicKey) {
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
function insecureTransactionHandling(transaction, privateKey) {
  // Sign transaction with minimal validation
  return signTransactionInsecure(transaction, privateKey);
}

// =============================================================================
// EXAMPLE 13: ETHEREUM PRIVATE KEY MANAGEMENT - SECURE
// =============================================================================

/**
 * Secure implementation of Ethereum private key management
 * 
 * Key security features:
 * - Properly encrypts private keys
 * - Uses strong KDF for password-based encryption
 * - Handles memory securely
 */

// File: secure-ethereum-keystore.js
const crypto = require('crypto');
const scrypt = require('scrypt-js');

// Function 1: Generate a secure Ethereum key
function generateSecureEthereumKey() {
  // Generate a secure random private key
  const privateKey = crypto.randomBytes(32);
  
  // Return the private key as hex
  return privateKey.toString('hex');
}

// Function 2: Encrypt a private key with a password
async function encryptPrivateKey(privateKey, password) {
  // Ensure privateKey is a Buffer
  if (typeof privateKey === 'string') {
    privateKey = Buffer.from(privateKey, 'hex');
  }
  
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
    cipher.update(privateKey),
    cipher.final()
  ]);
  
  // Create the keystore object
  const keystore = {
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
async function decryptPrivateKey(keystore, password) {
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
    kdfparams.n,
    kdfparams.r,
    kdfparams.p,
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
function usePrivateKeySecurely(privateKey, action) {
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
async function secureEthereumKeyManagement(password) {
  // Generate a new private key
  const privateKey = generateSecureEthereumKey();
  
  // Encrypt the private key
  const keystore = await encryptPrivateKey(privateKey, password);
  
  // Example of using the private key securely
  const result = usePrivateKeySecurely(privateKey, (key) => {
    // Mock action that uses the private key
    return `Action performed with key ending in ...${key.slice(-4)}`;
  });
  
  return {
    keystore,
    result
  };
}

// =============================================================================
// EXAMPLE 14: ETHEREUM PRIVATE KEY MANAGEMENT - INSECURE
// =============================================================================

/**
 * Insecure implementation of Ethereum private key management
 * 
 * Security issues:
 * - Weak encryption of private keys
 * - Poor password-based key derivation
 * - Insecure memory handling
 * - Interprocedural weakness where key material is mishandled across functions
 */

// File: insecure-ethereum-keystore.js
const crypto = require('crypto');

// Function 1: Generate an Ethereum key (INSECURE)
function generateInsecureEthereumKey() {
  // VULNERABILITY: Using Math.random for key generation
  // This is not cryptographically secure
  const privateKey = Buffer.alloc(32);
  for (let i = 0; i < privateKey.length; i++) {
    privateKey[i] = Math.floor(Math.random() * 256);
  }
  
  return privateKey.toString('hex');
}

// Function 2: Encrypt a private key with a password (INSECURE)
function encryptPrivateKeyInsecure(privateKey, password) {
  // Ensure privateKey is a Buffer
  if (typeof privateKey === 'string') {
    privateKey = Buffer.from(privateKey, 'hex');
  }
  
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
    cipher.update(privateKey),
    cipher.final()
  ]);
  
  // VULNERABILITY: No MAC to verify password correctness
  
  // Create the keystore object
  const keystore = {
    version: 1, // Non-standard version
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    salt: salt.toString('hex')
  };
  
  return keystore;
}

// Function 3: Decrypt a private key from a keystore (INSECURE)
function decryptPrivateKeyInsecure(keystore, password) {
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
    console.error(`Decryption error: ${error.message}`);
    return null;
  }
}

// Global variable to store private keys (INSECURE)
const privateKeyCache = new Map();

// Function 4: Use private key with caching (INSECURE)
function usePrivateKeyWithCaching(keystoreId, privateKey, action) {
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
function insecureEthereumKeyManagement(password) {
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

// =============================================================================
// EXAMPLE 15: CROSS-ORIGIN COMMUNICATION WITH CRYPTOGRAPHY - SECURE
// =============================================================================

/**
 * Secure implementation of cross-origin communication with cryptography
 * 
 * Key security features:
 * - Proper origin validation
 * - Message authentication
 * - Proper key handling
 */

// File: secure-cross-origin.js
// Parent window script

// Function 1: Generate a secure communication key
function generateSecureCommunicationKey() {
  // Generate a secure random key
  return crypto.getRandomValues(new Uint8Array(32));
}

// Function 2: Setup secure communication channel
function setupSecureCommunication(iframe, targetOrigin) {
  // Generate a secure key for communication
  const key = generateSecureCommunicationKey();
  
  // Store the key and target origin
  const channel = {
    key,
    targetOrigin,
    iframe
  };
  
  // Setup message listener
  window.addEventListener('message', event => {
    // Validate origin
    if (event.origin !== targetOrigin) {
      console.error(`Invalid origin: ${event.origin}`);
      return;
    }
    
    // Validate source
    if (event.source !== iframe.contentWindow) {
      console.error('Invalid source');
      return;
    }
    
    // Process the message
    processSecureMessage(event.data, channel);
  });
  
  return channel;
}

// Function 3: Send secure message to iframe
function sendSecureMessage(message, channel) {
  // Create a nonce
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  
  // Create HMAC for message authentication
  const msgData = JSON.stringify({ message, nonce: Array.from(nonce) });
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(msgData);
  
  // Create HMAC
  const hmac = createHmac(channel.key, msgBytes);
  
  // Send the message with HMAC
  channel.iframe.contentWindow.postMessage({
    data: msgData,
    hmac: Array.from(hmac)
  }, channel.targetOrigin);
}

// Function 4: Process secure message from iframe
function processSecureMessage(data, channel) {
  // Validate message format
  if (!data || !data.data || !data.hmac) {
    console.error('Invalid message format');
    return;
  }
  
  // Verify HMAC
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(data.data);
  const expectedHmac = createHmac(channel.key, msgBytes);
  
  // Constant-time comparison to prevent timing attacks
  if (!constantTimeEqual(expectedHmac, new Uint8Array(data.hmac))) {
    console.error('HMAC verification failed');
    return;
  }
  
  // Parse the message
  try {
    const parsedData = JSON.parse(data.data);
    
    // Process the message
    console.log('Received secure message:', parsedData.message);
    
    // Handle the message...
  } catch (error) {
    console.error('Failed to parse message:', error);
  }
}

// Helper function to create HMAC
function createHmac(key, data) {
  // In a browser environment, we would use SubtleCrypto
  // This is a simplified version for demonstration
  
  // Create a hash using key and data
  const combinedData = new Uint8Array(key.length + data.length);
  combinedData.set(key, 0);
  combinedData.set(data, key.length);
  
  // Create a hash of the combined data
  // (In a real implementation, this would use a proper HMAC function)
  const hashBuffer = crypto.subtle.digest('SHA-256', combinedData);
  
  return new Uint8Array(hashBuffer);
}

// Helper function for constant-time comparison
function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    // XOR the bytes - will be 0 for matching bytes
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
}

// Main function to initialize secure cross-origin communication
function secureIframeCommunication(iframeUrl) {
  // Create an iframe
  const iframe = document.createElement('iframe');
  iframe.src = iframeUrl;
  document.body.appendChild(iframe);
  
  // Extract origin from URL
  const targetOrigin = new URL(iframeUrl).origin;
  
  // Setup secure communication
  const channel = setupSecureCommunication(iframe, targetOrigin);
  
  // Return the channel for sending messages
  return {
    sendMessage: (message) => sendSecureMessage(message, channel)
  };
}

// =============================================================================
// EXAMPLE 16: CROSS-ORIGIN COMMUNICATION WITH CRYPTOGRAPHY - INSECURE
// =============================================================================

/**
 * Insecure implementation of cross-origin communication with cryptography
 * 
 * Security issues:
 * - Insufficient origin validation
 * - No message authentication
 * - Poor key handling
 * - Interprocedural weakness in message validation and handling
 */

// File: insecure-cross-origin.js
// Parent window script

// Global variable to store sensitive data (INSECURE)
let sensitiveData = null;

// Function 1: Setup insecure communication channel (INSECURE)
function setupInsecureCommunication(iframe) {
  // VULNERABILITY: No secure key generation
  // VULNERABILITY: No origin validation stored
  
  // Setup message listener
  window.addEventListener('message', event => {
    // VULNERABILITY: No origin validation
    // This allows any website to send messages
    
    // VULNERABILITY: No source validation
    // This allows any window to impersonate the iframe
    
    // Process the message
    processInsecureMessage(event.data);
  });
  
  return iframe;
}

// Function 2: Send insecure message to iframe (INSECURE)
function sendInsecureMessage(message, iframe) {
  // VULNERABILITY: No message authentication
  
  // VULNERABILITY: No origin restriction
  // Using '*' allows any origin to receive the message
  iframe.contentWindow.postMessage({
    data: JSON.stringify(message)
  }, '*');
}

// Function 3: Process insecure message from iframe (INSECURE)
function processInsecureMessage(data) {
  // VULNERABILITY: Minimal message validation
  if (!data || !data.data) {
    console.error('Invalid message format');
    return;
  }
  
  // VULNERABILITY: No message authentication
  
  // Parse the message
  try {
    const parsedData = JSON.parse(data.data);
    
    // VULNERABILITY: Storing sensitive data in a global variable
    sensitiveData = parsedData;
    
    // Process the message
    console.log('Received message:', parsedData);
    
    // VULNERABILITY: Executing data from the message
    if (parsedData.action === 'eval') {
      // SEVERE VULNERABILITY: Evaluating code from messages
      eval(parsedData.code);
    }
  } catch (error) {
    console.error('Failed to parse message:', error);
  }
}

// Function 4: Handle private key signing request (INSECURE)
function handleSigningRequest(data) {
  // VULNERABILITY: No validation of the request origin
  
  if (data.action === 'sign' && data.privateKey && data.message) {
    // VULNERABILITY: Accepting a private key through messaging
    const privateKey = data.privateKey;
    const message = data.message;
    
    // Perform signing
    const signature = signWithPrivateKey(privateKey, message);
    
    // VULNERABILITY: Sending the signature to an unvalidated origin
    window.parent.postMessage({
      action: 'signatureResult',
      signature,
      message
    }, '*');
    
    return signature;
  }
  
  return null;
}

// Main function to initialize insecure cross-origin communication
function insecureIframeCommunication(iframeUrl) {
  // Create an iframe
  const iframe = document.createElement('iframe');
  iframe.src = iframeUrl;
  document.body.appendChild(iframe);
  
  // Setup insecure communication
  setupInsecureCommunication(iframe);
  
  // Return an object for sending messages
  return {
    sendMessage: (message) => sendInsecureMessage(message, iframe)
  };
}

// =============================================================================
// EXAMPLE 17: SECURE RANDOM NUMBER GENERATION - SECURE
// =============================================================================

/**
 * Secure implementation of random number generation for cryptographic purposes
 * 
 * Key security features:
 * - Uses cryptographically secure random number generation
 * - Properly handles entropy
 * - Uses appropriate algorithms
 */

// File: secure-random.js
const crypto = require('crypto');

// Function 1: Generate a secure random number
function generateSecureRandomNumber(min, max) {
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
  let randomBytes;
  let randomValue;
  
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
function generateSecureRandomBuffer(size) {
  return crypto.randomBytes(size);
}

// Function 3: Generate a secure random string
function generateSecureRandomString(length, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
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
function generateSecureKey(type = 'AES-256') {
  let keyLength;
  
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
function secureRandomOperations() {
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

// =============================================================================
// EXAMPLE 18: SECURE RANDOM NUMBER GENERATION - INSECURE
// =============================================================================

/**
 * Insecure implementation of random number generation for cryptographic purposes
 * 
 * Security issues:
 * - Uses non-cryptographic random number generation
 * - Insufficient entropy sources
 * - Predictable outputs
 * - Interprocedural weakness where insecure randomness affects crypto operations
 */

// File: insecure-random.js

// Function 1: Generate an insecure random number (INSECURE)
function generateInsecureRandomNumber(min, max) {
  // VULNERABILITY: Using Math.random() which is not cryptographically secure
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Function 2: Generate an insecure random buffer (INSECURE)
function generateInsecureRandomBuffer(size) {
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
function generatePseudoRandomString(length, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
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
  const random = () => {
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
function generateInsecureKey(type = 'AES-256') {
  let keyLength;
  
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

// Function 5: Encrypt data with insecure key (INSECURE)
function encryptWithInsecureKey(data, type = 'AES-256') {
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
function insecureRandomOperations(data) {
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

// =============================================================================
// EXAMPLE 19: HTTP COMMUNICATION WITH TLS - SECURE
// =============================================================================

/**
 * Secure implementation of HTTP communication with TLS
 * 
 * Key security features:
 * - Proper certificate validation
 * - Strong cipher suites
 * - Secure protocols
 */

// File: secure-tls.js
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');

// Function 1: Create secure HTTPS options
function createSecureHttpsOptions() {
  return {
    // Minimum TLS version
    minVersion: 'TLSv1.2',
    
    // Prefer modern ciphers
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384',
    
    // Secure options
    honorCipherOrder: true,
    
    // Enable OCSP stapling
    requestOCSP: true,
    
    // Reject unauthorized certificates
    rejectUnauthorized: true
  };
}

// Function 2: Make secure HTTPS request
function makeSecureHttpsRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    // Parse the URL
    const parsedUrl = new URL(url);
    
    // Merge options with secure defaults
    const requestOptions = {
      ...createSecureHttpsOptions(),
      ...options,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 443,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET'
    };
    
    // Create the request
    const req = https.request(requestOptions, (res) => {
      // Check for secure redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // Ensure redirects only go to HTTPS URLs
        const redirectUrl = new URL(res.headers.location, url);
        if (redirectUrl.protocol !== 'https:') {
          reject(new Error('Insecure redirect detected'));
          return;
        }
      }
      
      // Collect the response data
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data
        });
      });
    });
    
    // Handle errors
    req.on('error', (error) => {
      reject(error);
    });
    
    // Send request body if provided
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

// Function 3: Validate certificate
function validateCertificate(cert, hostname) {
  // Check certificate validity period
  const now = Date.now();
  const certNotBefore = new Date(cert.valid_from).getTime();
  const certNotAfter = new Date(cert.valid_to).getTime();
  
  if (now < certNotBefore || now > certNotAfter) {
    return {
      valid: false,
      reason: 'Certificate is not valid at the current time'
    };
  }
  
  // Check hostname
  const altNames = cert.subjectaltname;
  if (altNames) {
    const names = altNames.split(', ').map(name => {
      const [type, value] = name.split(':');
      return { type, value };
    });
    
    // Check if hostname matches any of the alt names
    const hostnameMatch = names.some(name => {
      if (name.type === 'DNS') {
        // Check for wildcard certificates
        if (name.value.startsWith('*.')) {
          const wildcardDomain = name.value.slice(2);
          const hostnameParts = hostname.split('.');
          hostnameParts.shift();
          const hostnameDomain = hostnameParts.join('.');
          return hostnameDomain === wildcardDomain;
        }
        
        return name.value === hostname;
      }
      return false;
    });
    
    if (!hostnameMatch) {
      return {
        valid: false,
        reason: 'Certificate does not match hostname'
      };
    }
  }
  
  return {
    valid: true
  };
}

// Function 4: Pin certificates
function configureCertificatePinning(hostname, publicKeyHash) {
  // Return a checking function for the specified hostname and public key hash
  return (cert) => {
    // Get the public key from the certificate
    const publicKey = cert.pubkey;
    
    // Hash the public key
    const hash = crypto.createHash('sha256').update(publicKey).digest('base64');
    
    // Compare with the pinned hash
    return hash === publicKeyHash;
  };
}

// Main function for secure TLS communication
async function secureTlsCommunication(url, pinningConfig = null) {
  try {
    // Create options with secure defaults
    const options = createSecureHttpsOptions();
    
    // Add certificate pinning if provided
    if (pinningConfig) {
      options.checkServerIdentity = (hostname, cert) => {
        // First validate the certificate
        const validation = validateCertificate(cert, hostname);
        if (!validation.valid) {
          return new Error(validation.reason);
        }
        
        // Then check certificate pinning
        const pinChecker = configureCertificatePinning(hostname, pinningConfig.publicKeyHash);
        if (!pinChecker(cert)) {
          return new Error('Certificate public key does not match pinned hash');
        }
        
        return undefined; // Certificate is valid
      };
    }
    
    // Make the secure request
    const response = await makeSecureHttpsRequest(url, options);
    
    return response;
  } catch (error) {
    console.error(`Secure TLS communication error: ${error.message}`);
    throw error;
  }
}

// =============================================================================
// EXAMPLE 20: HTTP COMMUNICATION WITH TLS - INSECURE
// =============================================================================

/**
 * Insecure implementation of HTTP communication with TLS
 * 
 * Security issues:
 * - Disabled certificate validation
 * - Weak cipher suites
 * - Outdated protocols
 * - Interprocedural weakness where security settings propagate
 */

// File: insecure-tls.js
const https = require('https');
const tls = require('tls');

// Function 1: Create insecure HTTPS options (INSECURE)
function createInsecureHttpsOptions() {
  return {
    // VULNERABILITY: Allowing old TLS versions
    minVersion: 'TLSv1',
    
    // VULNERABILITY: Allowing weak ciphers
    ciphers: 'HIGH:MEDIUM:LOW:!aNULL:!eNULL',
    
    // VULNERABILITY: Disabling certificate validation
    rejectUnauthorized: false
  };
}

// Global variable to store insecure options (INSECURE)
const globalInsecureOptions = createInsecureHttpsOptions();

// Function 2: Make insecure HTTPS request (INSECURE)
function makeInsecureHttpsRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    // Parse the URL
    const parsedUrl = new URL(url);
    
    // VULNERABILITY: Merging with global insecure options
    // This affects all requests using this function
    const requestOptions = {
      ...globalInsecureOptions,
      ...options,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 443,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET'
    };
    
    // Create the request
    const req = https.request(requestOptions, (res) => {
      // VULNERABILITY: Not validating secure redirects
      
      // Collect the response data
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data
        });
      });
    });
    
    // Handle errors
    req.on('error', (error) => {
      // VULNERABILITY: Silently continuing on some errors
      if (error.code === 'CERT_HAS_EXPIRED' || error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
        console.error(`Certificate error (ignored): ${error.message}`);
        resolve({
          statusCode: 0,
          headers: {},
          data: '',
          error: error.message
        });
      } else {
        reject(error);
      }
    });
    
    // Send request body if provided
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

// Function 3: Custom certificate validator that accepts all (INSECURE)
function acceptAllCertificates() {
  // VULNERABILITY: Accepting all certificates without validation
  return (hostname, cert) => {
    // Always return undefined (no error) to accept any certificate
    return undefined;
  };
}

// Function 4: Make request with custom domain (INSECURE)
async function makeRequestWithCustomDomain(url, targetDomain) {
  // Parse the URL
  const parsedUrl = new URL(url);
  
  // VULNERABILITY: Overriding the domain to connect to
  // This can be used to bypass certificate validation
  const options = {
    ...createInsecureHttpsOptions(),
    hostname: targetDomain,
    servername: parsedUrl.hostname, // SNI will still use the original hostname
    headers: {
      'Host': parsedUrl.hostname // HTTP Host header will be the original
    },
    path: parsedUrl.pathname + parsedUrl.search,
    method: 'GET'
  };
  
  // VULNERABILITY: Bypassing certificate validation
  options.checkServerIdentity = acceptAllCertificates();
  
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data
        });
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.end();
  });
}

// Main function for insecure TLS communication
async function insecureTlsCommunication(url, bypassDomain = null) {
  try {
    // VULNERABILITY: Conditionally using certificate bypassing
    if (bypassDomain) {
      // Use domain bypassing
      return await makeRequestWithCustomDomain(url, bypassDomain);
    } else {
      // Use standard insecure request
      return await makeInsecureHttpsRequest(url);
    }
  } catch (error) {
    console.error(`TLS communication error: ${error.message}`);
    // VULNERABILITY: Retrying with certificate validation disabled
    console.log('Retrying with certificate validation disabled...');
    return await makeInsecureHttpsRequest(url, { rejectUnauthorized: false });
  }
}

/* 
 * DATASET CONCLUSION
 * ==================
 * 
 * This dataset contains 20 examples (10 secure, 10 insecure) of cryptographic
 * API usage specifically focused on cryptocurrency and related operations.
 * Each example demonstrates interprocedural patterns where security properties
 * must be maintained across function boundaries.
 * 
 * Key security topics covered:
 * - HD wallet seed generation and derivation
 * - Transaction signing with ECDSA
 * - Key storage in browser extensions
 * - BIP32/39/44 derivation path handling
 * - Nonce generation for ECDSA signatures
 * - Transaction data integrity
 * - Ethereum private key management
 * - Cross-origin communication with cryptography
 * - Secure random number generation
 * - HTTP communication with TLS
 * 
 * Each example is labeled clearly as secure or insecure, with comments
 * explaining the security issues in the insecure examples.
 */