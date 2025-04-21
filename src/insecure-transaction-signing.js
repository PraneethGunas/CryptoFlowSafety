/**
 * Insecure implementation of ECDSA transaction signing
 * 
 * Security issues:
 * - Uses custom implementation with non-deterministic k-value
 * - Non-deterministic k-value can lead to private key leakage if reused
 * - Interprocedural weakness where nonce generation affects signing security
 */

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

module.exports = {
  derivePrivateKeyInsecure,
  createTransactionInsecure,
  generateInsecureNonce,
  signTransactionInsecure,
  createAndSignTransactionInsecure
};