# Interprocedural Cryptographic API Misuse Dataset (TypeScript)

## 🔐 Overview

This dataset provides comprehensive examples of secure and insecure cryptographic API usage patterns in cryptocurrency-related applications. Unlike traditional datasets that focus on single-function (intraprocedural) vulnerabilities, this collection specifically demonstrates how security properties propagate across function and module boundaries.

The examples highlight critical vulnerabilities that can lead to real financial losses in cryptocurrency applications, making this dataset particularly valuable for security researchers and developers working with cryptographic APIs.

## 🎯 Purpose

This dataset serves multiple purposes:

1. **Educational resource** for developers to understand secure and insecure cryptographic patterns
2. **Testing dataset** for tools that analyze interprocedural cryptographic API misuses
3. **Reference implementation** for secure cryptocurrency operations
4. **Benchmark** for evaluating static and dynamic analysis tools
5. **Type safety demonstration** showing how TypeScript can help catch some issues at compile time

## 📚 Contents

The dataset contains 20 examples (10 secure, 10 insecure) covering the following security-critical areas:

| ID | Topic | Secure Example | Insecure Example |
|----|-------|---------------|-----------------|
| 1-2 | HD Wallet Seed Generation | `secure-wallet-generation.ts` | `insecure-wallet-generation.ts` |
| 3-4 | Transaction Signing | `secure-transaction-signing.ts` | `insecure-transaction-signing.ts` |
| 5-6 | Browser Extension Key Storage | `secure-browser-extension.ts` | `insecure-browser-extension.ts` |
| 7-8 | BIP32/39/44 Derivation Path | `secure-derivation-path.ts` | `insecure-derivation-path.ts` |
| 9-10 | ECDSA Nonce Generation | `secure-nonce-generation.ts` | `insecure-nonce-generation.ts` |
| 11-12 | Transaction Data Integrity | `secure-transaction-verification.ts` | `insecure-transaction-verification.ts` |
| 13-14 | Ethereum Key Management | `secure-ethereum-keystore.ts` | `insecure-ethereum-keystore.ts` |
| 15-16 | Cross-Origin Communication | `secure-cross-origin.ts` | `insecure-cross-origin.ts` |
| 17-18 | Random Number Generation | `secure-random.ts` | `insecure-random.ts` |
| 19-20 | TLS Communication | `secure-tls.ts` | `insecure-tls.ts` |

Each example is heavily documented with comments explaining:
- The overall purpose of the code
- Key security features (in secure examples)
- Specific vulnerabilities (in insecure examples)
- How vulnerabilities propagate across function boundaries (interprocedural aspects)

## TypeScript Advantages

The TypeScript implementation adds several benefits:

1. **Type Safety**: Explicit types help catch many errors at compile time
2. **Interface Definitions**: Clear interfaces for all data structures
3. **Better IDE Support**: Improved autocomplete, hover information, and error detection
4. **Clearer Documentation**: Type annotations serve as inline documentation
5. **Safer Refactoring**: Types make it safer to modify and extend code

## 🚀 Getting Started

### Prerequisites

- Node.js (v14.0.0 or higher)
- npm (v6.0.0 or higher)

### Installation

1. Clone this repository:
```bash
git clone https://github.com/PraneethGunas/crypto-api-misuse-dataset.git
cd crypto-api-misuse-dataset
```

2. Install dependencies:
```bash
npm install
```

3. Build the TypeScript code:
```bash
npm run build
```

### Running Examples

Each example can be run individually for demonstration purposes. We've included utility scripts to run and explain each example:

```bash
# Run a secure example
npm run demo:secure wallet-generation

# Run an insecure example
npm run demo:insecure transaction-signing

# Run a specific function from an example
npm run demo:function secure-wallet-generation generateSecureEntropy

# List all available examples
npm run list

# Get detailed explanation comparing secure and insecure implementations
npm run explain wallet-generation
```

> ⚠️ **WARNING**: The insecure examples contain deliberate vulnerabilities for educational purposes. Never use these in production environments.

## 📝 Example Structure

Each example follows a consistent structure to facilitate learning and analysis:

```typescript
/**
 * Secure/Insecure implementation of [TOPIC]
 * 
 * Key security features/Security issues:
 * - Feature/Issue 1
 * - Feature/Issue 2
 * - ...
 */

// Function 1: [Purpose]
export function doSomething(param1: Type, param2: Type): ReturnType {
  // Implementation with detailed comments
}

// Function 2: [Purpose]
export function doSomethingElse(param1: Type): ReturnType {
  // Implementation with detailed comments
}

// Main function to demonstrate the interprocedural flow
export function mainFunction(input: InputType): OutputType {
  // Shows how data/control flows between functions
}
```

## 🔍 Key Interprocedural Patterns

This dataset highlights several critical interprocedural patterns:

1. **Entropy Flow**: How randomness quality propagates across function boundaries
2. **Key Material Handling**: How private keys are managed across different components
3. **Validation Chains**: How input validation (or lack thereof) affects security across functions
4. **Cross-Boundary Data Flow**: How sensitive data moves between contexts (e.g., browser extension components)
5. **Error Propagation**: How errors and exceptions affect security properties

## 📊 Using for Analysis

### Static Analysis

This dataset is designed to be analyzed with static analysis tools. Example approaches:

1. **Taint Tracking**: Track flow of sensitive data (private keys, entropy) through function calls
2. **Call Graph Analysis**: Identify vulnerable paths in the call graph
3. **Pattern Matching**: Detect known vulnerability patterns across function boundaries

### Dynamic Analysis

The examples can also be instrumented for dynamic analysis:

1. **Fuzzing**: Test boundaries with different inputs to expose vulnerabilities
2. **Runtime Verification**: Monitor security properties during execution
3. **API Usage Monitoring**: Detect misuse patterns during runtime

## 🔗 Integration with Analysis Tools

### ESLint

We've included ESLint configurations to demonstrate how to detect some of these issues with static analysis:

```bash
# Run ESLint analysis on all examples
npm run lint

# Run only security-focused rules
npm run lint:security
```

### Custom Analysis Scripts

The repository includes custom analysis scripts that demonstrate how to detect specific vulnerabilities:

```bash
# Run all analysis scripts
npm run analyze

# Run specific analysis
npm run analyze:entropy-propagation
npm run analyze:key-exposure
```

## ⚙️ Extending the Dataset

You can extend this dataset with your own examples:

1. Follow the naming convention: `[secure|insecure]-[topic].ts`
2. Include detailed comments explaining security features or vulnerabilities
3. Demonstrate interprocedural flows
4. Add your example to the test suite in `test/`

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-example`)
3. Commit your changes (`git commit -m 'Add some amazing example'`)
4. Push to the branch (`git push origin feature/amazing-example`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔒 Security Best Practices

Here are key takeaways from the secure examples:

1. **Entropy**: Always use cryptographically secure random number generators (e.g., `crypto.randomBytes()`)
2. **Nonces**: Use deterministic nonces (RFC 6979) for ECDSA signatures
3. **Key Storage**: Encrypt private keys before storage and use secure storage APIs
4. **Validation**: Validate all inputs, especially derivation paths and transaction data
5. **Origin Checking**: Always validate message origins in cross-origin communication
6. **Certificate Validation**: Never disable TLS certificate validation

## ⚠️ Common Vulnerabilities Demonstrated

The insecure examples demonstrate these common vulnerabilities:

1. **Weak Entropy**: Using `Math.random()` for cryptographic operations
2. **Nonce Reuse**: Reusing or predictably generating ECDSA nonces
3. **Insecure Storage**: Storing unencrypted private keys
4. **Insufficient Validation**: Missing validation of critical cryptographic parameters
5. **Origin Bypassing**: Not validating message origins
6. **Certificate Bypassing**: Disabling TLS certificate validation

## 📚 Further Reading

For more information about cryptographic API misuses:

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards and Guidelines](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Bitcoin Developer Documentation](https://developer.bitcoin.org/devguide/index.html)
- [CryptoAPI-Bench: A Comprehensive Benchmark on Java Cryptographic API Misuses](https://arxiv.org/abs/1812.03452)

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.