/**
 * Insecure implementation of nonce generation for ECDSA signatures
 * 
 * Security issues:
 * - Uses predictable/reused nonce for ECDSA
 * - Nonce reuse can lead to private key extraction
 * - Interprocedural weakness where nonce generation affects signing security
 */

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

module.exports = {
  generateInsecureNonce,
  signWithInsecureNonce,
  signMultipleMessagesInsecure,
  insecureSignMessages
};