/**
 * Interprocedural Cryptographic API Misuse Dataset
 * 
 * This module exports all the secure and insecure implementations
 * for use in analysis and demonstration.
 */

// 1-2. HD Wallet Seed Generation
import * as secureWalletGeneration from './secure-wallet-generation';
import * as insecureWalletGeneration from './insecure-wallet-generation';

// 3-4. Transaction Signing with ECDSA
import * as secureTransactionSigning from './secure-transaction-signing';
import * as insecureTransactionSigning from './insecure-transaction-signing';

// 5-6. Browser Extension Key Storage
import * as secureBrowserExtension from './secure-browser-extension';
import * as insecureBrowserExtension from './insecure-browser-extension';

// 7-8. BIP32/39/44 Derivation Path
import * as secureDerivationPath from './secure-derivation-path';
import * as insecureDerivationPath from './insecure-derivation-path';

// 9-10. ECDSA Nonce Generation
import * as secureNonceGeneration from './secure-nonce-generation';
import * as insecureNonceGeneration from './insecure-nonce-generation';

// 11-12. Transaction Data Integrity
import * as secureTransactionVerification from './secure-transaction-verification';
import * as insecureTransactionVerification from './insecure-transaction-verification';

// 13-14. Ethereum Key Management
import * as secureEthereumKeystore from './secure-ethereum-keystore';
import * as insecureEthereumKeystore from './insecure-ethereum-keystore';

// 15-16. Cross-Origin Communication
import * as secureCrossOrigin from './secure-cross-origin';
import * as insecureCrossOrigin from './insecure-cross-origin';

// 17-18. Random Number Generation
import * as secureRandom from './secure-random';
import * as insecureRandom from './insecure-random';

// 19-20. TLS Communication
import * as secureTls from './secure-tls';
import * as insecureTls from './insecure-tls';

export {
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
};