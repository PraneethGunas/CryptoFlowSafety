/**
 * Insecure implementation of HD wallet seed generation
 * 
 * Security issues:
 * - Uses Math.random() which is not cryptographically secure
 * - Weak entropy generation could lead to predictable wallets
 * - Seed can be potentially recovered by attackers
 * - Interprocedural weakness where weak entropy propagates across functions
 */

import * as bip39 from 'bip39';
import { WalletResult } from './types/common';

// Function 1: Generate insecure entropy (INSECURE)
export function generateWeakEntropy(bits: number = 256): Buffer {
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
export function generateMnemonicInsecure(entropy: Buffer): string {
  // This function itself is implemented correctly
  // but it's receiving weak entropy from the caller
  const mnemonic = bip39.entropyToMnemonic(entropy);
  return mnemonic;
}

// Function 3: Create seed from mnemonic
export function createSeedFromMnemonicInsecure(mnemonic: string, passphrase: string = ''): Buffer {
  // This function is implemented correctly
  // but it's using a mnemonic generated from weak entropy
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  return seed;
}

// Main wallet creation function
export function createInsecureWallet(passphrase: string = ''): WalletResult {
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