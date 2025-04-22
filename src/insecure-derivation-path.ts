/**
 * Insecure implementation of BIP32/39/44 for derivation path handling
 * 
 * Security issues:
 * - No validation of derivation paths
 * - Attempts to derive hardened paths from xpub
 * - Doesn't enforce proper BIP44 structure
 * - Interprocedural weakness where validation failures propagate
 */

import * as bip32 from 'bip32';
import * as bip39 from 'bip39';

interface Address {
  path: string;
  address: string;
}

// Function 1: Parse derivation path without validation (INSECURE)
export function parseDerivationPathInsecure(path: string): string {
  // VULNERABILITY: No validation of the path format
  // Simply removes the m/ prefix if present
  return path.startsWith('m/') ? path.slice(2) : path;
}

// Function 2: Derive a node from seed and path (INSECURE)
export function deriveNodeFromSeedInsecure(seed: string, path: string): bip32.BIP32Interface | null {
  // VULNERABILITY: No validation of the derivation path
  try {
    // Create master node
    const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));
    
    // Derive child node without validation
    return masterNode.derivePath(path);
  } catch (error) {
    // VULNERABILITY: Silently catching errors
    console.error(`Error: ${(error as Error).message}`);
    return null;
  }
}

// Function 3: Derive a node from xpub and path (INSECURE)
export function deriveNodeFromXpubInsecure(xpub: string, path: string): bip32.BIP32Interface | null {
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
    console.error(`Error: ${(error as Error).message}`);
    return null;
  }
}

// Function 4: Generate addresses from a path (INSECURE)
export function generateAddressesInsecure(
  seedOrXpub: string, 
  startIndex: number, 
  count: number, 
  change: number = 0, 
  isSeed: boolean = true
): Address[] {
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
  const addresses: Address[] = [];
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
      console.error(`Error generating address ${i}: ${(error as Error).message}`);
    }
  }
  
  return addresses;
}

// Main function to handle wallet derivation insecurely
export function insecureWalletDerivation(
  seedOrXpub: string, 
  startIndex: number = 0, 
  count: number = 5, 
  isSeed: boolean = true
): Address[] {
  return generateAddressesInsecure(seedOrXpub, startIndex, count, 0, isSeed);
}