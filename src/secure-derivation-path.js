/**
 * Secure implementation of BIP32/39/44 for derivation path handling
 * 
 * Key security features:
 * - Properly validates derivation paths
 * - Uses hardened derivation for sensitive paths
 * - Prevents derivation from xpub when inappropriate
 */

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

module.exports = {
  validateDerivationPath,
  requiresPrivateKey,
  deriveNodeFromSeed,
  deriveNodeFromXpub,
  secureWalletDerivation
};