/**
 * Secure implementation of HD wallet seed generation
 * 
 * Key security features:
 * - Uses crypto.getRandomValues for strong entropy
 * - Proper mnemonic generation using BIP39
 * - Functions are properly separated but maintain security across boundaries
 */

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

module.exports = {
  generateSecureEntropy,
  generateMnemonic,
  createSeedFromMnemonic,
  createSecureWallet
};