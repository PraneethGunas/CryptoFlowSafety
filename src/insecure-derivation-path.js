/**
 * Insecure implementation of BIP32/39/44 for derivation path handling
 * 
 * Security issues:
 * - No validation of derivation paths
 * - Attempts to derive hardened paths from xpub
 * - Doesn't enforce proper BIP44 structure
 * - Interprocedural weakness where validation failures propagate
 */

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

module.exports = {
  parseDerivationPathInsecure,
  deriveNodeFromSeedInsecure,
  deriveNodeFromXpubInsecure,
  generateAddressesInsecure,
  insecureWalletDerivation
};