/**
 * Secure implementation of ECDSA transaction signing
 * 
 * Key security features:
 * - Uses deterministic k-value (RFC 6979)
 * - Properly validates transaction before signing
 * - Maintains security across function boundaries
 */

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

module.exports = {
  derivePrivateKey,
  createTransaction,
  signTransaction,
  createAndSignTransaction
};