/**
 * Secure implementation of HD wallet seed generation
 * 
 * Key security features:
 * - Uses crypto.getRandomValues for strong entropy
 * - Proper mnemonic generation using BIP39
 * - Functions are properly separated but maintain security across boundaries
 */

import * as bip39 from 'bip39';
import * as crypto from 'crypto';
import { WalletResult } from './types/common';

// Function 1: Generate secure entropy
export function generateSecureEntropy(bits: number = 256): Buffer {
  // Use a cryptographically secure random number generator
  const buffer = crypto.randomBytes(bits / 8);
  return buffer;
}

// Function 2: Generate mnemonic from entropy
export function generateMnemonic(entropy: Buffer): string {
  // Use BIP39 to convert entropy to mnemonic
  const mnemonic = bip39.entropyToMnemonic(entropy);
  return mnemonic;
}

// Function 3: Create seed from mnemonic
export function createSeedFromMnemonic(mnemonic: string, passphrase: string = ''): Buffer {
  // Generate seed using BIP39
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  return seed;
}

// Main wallet creation function
export function createSecureWallet(passphrase: string = ''): WalletResult {
  const entropy = generateSecureEntropy(256);
  const mnemonic = generateMnemonic(entropy);
  const seed = createSeedFromMnemonic(mnemonic, passphrase);
  
  return {
    mnemonic,
    seed: seed.toString('hex')
  };
}