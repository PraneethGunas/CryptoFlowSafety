/* 
 * DATASET: Interprocedural Cryptographic API Misuse
 * ================================================
 * 
 * This dataset contains examples of secure and insecure cryptographic API usage
 * across multiple functions, specifically focused on cryptocurrency operations.
 */

// Import all examples from the src modules
import {
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
} from './src/index';

// Create an object with all examples organized by category
export const cryptoAPIDataset = {
  // HD Wallet Seed Generation
  walletGeneration: {
    secure: secureWalletGeneration,
    insecure: insecureWalletGeneration
  },
  
  // Transaction Signing with ECDSA
  transactionSigning: {
    secure: secureTransactionSigning,
    insecure: insecureTransactionSigning
  },
  
  // Browser Extension Key Storage
  browserExtension: {
    secure: secureBrowserExtension,
    insecure: insecureBrowserExtension
  },
  
  // BIP32/39/44 Derivation Path
  derivationPath: {
    secure: secureDerivationPath,
    insecure: insecureDerivationPath
  },
  
  // ECDSA Nonce Generation
  nonceGeneration: {
    secure: secureNonceGeneration,
    insecure: insecureNonceGeneration
  },
  
  // Transaction Data Integrity
  transactionVerification: {
    secure: secureTransactionVerification,
    insecure: insecureTransactionVerification
  },
  
  // Ethereum Key Management
  ethereumKeystore: {
    secure: secureEthereumKeystore,
    insecure: insecureEthereumKeystore
  },
  
  // Cross-Origin Communication
  crossOrigin: {
    secure: secureCrossOrigin,
    insecure: insecureCrossOrigin
  },
  
  // Random Number Generation
  randomGeneration: {
    secure: secureRandom,
    insecure: insecureRandom
  },
  
  // TLS Communication
  tlsCommunication: {
    secure: secureTls,
    insecure: insecureTls
  }
};

// Export individual modules for easier direct access
export {
  secureWalletGeneration,
  insecureWalletGeneration,
  secureTransactionSigning,
  insecureTransactionSigning,
  secureBrowserExtension,
  insecureBrowserExtension,
  secureDerivationPath,
  insecureDerivationPath,
  secureNonceGeneration,
  insecureNonceGeneration,
  secureTransactionVerification,
  insecureTransactionVerification,
  secureEthereumKeystore,
  insecureEthereumKeystore,
  secureCrossOrigin,
  insecureCrossOrigin,
  secureRandom,
  insecureRandom,
  secureTls,
  insecureTls
};

/* 
 * DATASET CONCLUSION
 * ==================
 * 
 * This dataset contains 20 examples (10 secure, 10 insecure) of cryptographic
 * API usage specifically focused on cryptocurrency and related operations.
 * Each example demonstrates interprocedural patterns where security properties
 * must be maintained across function boundaries.
 * 
 * Key security topics covered:
 * - HD wallet seed generation and derivation
 * - Transaction signing with ECDSA
 * - Key storage in browser extensions
 * - BIP32/39/44 derivation path handling
 * - Nonce generation for ECDSA signatures
 * - Transaction data integrity
 * - Ethereum private key management
 * - Cross-origin communication with cryptography
 * - Secure random number generation
 * - HTTP communication with TLS
 * 
 * Each example is implemented as a TypeScript module with secure and insecure
 * implementations clearly labeled and documented. The security vulnerabilities
 * in the insecure examples are highlighted with comments explaining the issues.
 */