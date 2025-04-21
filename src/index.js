/**
 * Interprocedural Cryptographic API Misuse Dataset
 * 
 * This module exports all the secure and insecure implementations
 * for use in analysis and demonstration.
 */

// 1-2. HD Wallet Seed Generation
const secureWalletGeneration = require('./secure-wallet-generation');
const insecureWalletGeneration = require('./insecure-wallet-generation');

// 3-4. Transaction Signing with ECDSA
const secureTransactionSigning = require('./secure-transaction-signing');
const insecureTransactionSigning = require('./insecure-transaction-signing');

// 5-6. Browser Extension Key Storage
const secureBrowserExtension = require('./secure-browser-extension');
const insecureBrowserExtension = require('./insecure-browser-extension');

// 7-8. BIP32/39/44 Derivation Path
const secureDerivationPath = require('./secure-derivation-path');
const insecureDerivationPath = require('./insecure-derivation-path');

// 9-10. ECDSA Nonce Generation
const secureNonceGeneration = require('./secure-nonce-generation');
const insecureNonceGeneration = require('./insecure-nonce-generation');

// 11-12. Transaction Data Integrity
const secureTransactionVerification = require('./secure-transaction-verification');
const insecureTransactionVerification = require('./insecure-transaction-verification');

// 13-14. Ethereum Key Management
const secureEthereumKeystore = require('./secure-ethereum-keystore');
const insecureEthereumKeystore = require('./insecure-ethereum-keystore');

// 15-16. Cross-Origin Communication
const secureCrossOrigin = require('./secure-cross-origin');
const insecureCrossOrigin = require('./insecure-cross-origin');

// 17-18. Random Number Generation
const secureRandom = require('./secure-random');
const insecureRandom = require('./insecure-random');

// 19-20. TLS Communication
const secureTls = require('./secure-tls');
const insecureTls = require('./insecure-tls');

module.exports = {
  // HD Wallet Seed Generation
  secureWalletGeneration,
  insecureWalletGeneration,
  
  // Transaction Signing with ECDSA
  secureTransactionSigning,
  insecureTransactionSigning,
  
  // Browser Extension Key Storage
  secureBrowserExtension,
  insecureBrowserExtension,
  
  // BIP32/39/44 Derivation Path
  secureDerivationPath,
  insecureDerivationPath,
  
  // ECDSA Nonce Generation
  secureNonceGeneration,
  insecureNonceGeneration,
  
  // Transaction Data Integrity
  secureTransactionVerification,
  insecureTransactionVerification,
  
  // Ethereum Key Management
  secureEthereumKeystore,
  insecureEthereumKeystore,
  
  // Cross-Origin Communication
  secureCrossOrigin,
  insecureCrossOrigin,
  
  // Random Number Generation
  secureRandom,
  insecureRandom,
  
  // TLS Communication
  secureTls,
  insecureTls,
  
  // Export individual functions for easier access
  
  // Secure implementations
  createSecureWallet: secureWalletGeneration.createSecureWallet,
  createAndSignTransaction: secureTransactionSigning.createAndSignTransaction,
  secureWalletDerivation: secureDerivationPath.secureWalletDerivation,
  secureSignMessage: secureNonceGeneration.secureSignMessage,
  secureTransactionHandling: secureTransactionVerification.secureTransactionHandling,
  secureEthereumKeyManagement: secureEthereumKeystore.secureEthereumKeyManagement,
  secureIframeCommunication: secureCrossOrigin.secureIframeCommunication,
  secureRandomOperations: secureRandom.secureRandomOperations,
  secureTlsCommunication: secureTls.secureTlsCommunication,
  
  // Insecure implementations
  createInsecureWallet: insecureWalletGeneration.createInsecureWallet,
  createAndSignTransactionInsecure: insecureTransactionSigning.createAndSignTransactionInsecure,
  insecureWalletDerivation: insecureDerivationPath.insecureWalletDerivation,
  insecureSignMessages: insecureNonceGeneration.insecureSignMessages,
  insecureTransactionHandling: insecureTransactionVerification.insecureTransactionHandling,
  insecureEthereumKeyManagement: insecureEthereumKeystore.insecureEthereumKeyManagement,
  insecureIframeCommunication: insecureCrossOrigin.insecureIframeCommunication,
  insecureRandomOperations: insecureRandom.insecureRandomOperations,
  insecureTlsCommunication: insecureTls.insecureTlsCommunication
};