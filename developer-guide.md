# Developer Guide: Secure Cryptographic API Usage

This guide provides practical advice for developers working with cryptographic APIs, specifically in cryptocurrency applications. It draws lessons from the examples in this dataset to help you implement secure cryptographic operations.

## 🔑 General Principles

1. **Never Roll Your Own Crypto**
   - Use established libraries for cryptographic operations
   - Follow standard implementations of cryptographic protocols
   - Avoid custom implementations of cryptographic primitives

2. **Maintain Security Across Boundaries**
   - Track sensitive data as it moves between functions
   - Validate inputs at each boundary
   - Don't assume data has been validated by the caller

3. **Design for Failure**
   - Handle errors securely without leaking sensitive information
   - Don't silently continue after cryptographic failures
   - Consider what happens when components fail

## 📚 Specific Recommendations

### Entropy and Randomness

✅ **Do:**
- Use `crypto.getRandomValues()` (browser) or `crypto.randomBytes()` (Node.js)
- Ensure sufficient entropy for cryptographic seeds (≥ 256 bits)
- Validate the source of entropy for critical operations

❌ **Don't:**
- Use `Math.random()` for any cryptographic purpose
- Seed random number generators with predictable values
- Reuse entropy for multiple operations

```javascript
// SECURE: Use cryptographically secure random number generation
const secureEntropy = crypto.randomBytes(32);

// INSECURE: Using Math.random() for cryptographic operations
const insecureEntropy = Buffer.alloc(32);
for (let i = 0; i < 32; i++) {
  insecureEntropy[i] = Math.floor(Math.random() * 256);
}
```

### Key Management

✅ **Do:**
- Encrypt private keys before storage
- Use strong key derivation functions (e.g., PBKDF2, scrypt)
- Limit the lifetime of keys in memory

❌ **Don't:**
- Store unencrypted private keys
- Transmit private keys between components
- Cache private keys in memory longer than necessary

```javascript
// SECURE: Properly encrypt a private key before storage
async function encryptPrivateKey(privateKey, password) {
  const salt = crypto.randomBytes(32);
  const key = await pbkdf2(password, salt, 100000, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    salt: salt.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// INSECURE: Storing an unencrypted private key
function storeUnencryptedKey(privateKey) {
  localStorage.setItem('privateKey', privateKey); // Never do this!
}
```

### Transaction Signing

✅ **Do:**
- Use deterministic signatures (RFC 6979) for ECDSA
- Validate transaction data before signing
- Keep private keys isolated from transaction construction

❌ **Don't:**
- Generate random nonces for ECDSA signatures
- Sign transactions with minimal validation
- Expose private keys to untrusted contexts

```javascript
// SECURE: Using deterministic nonce generation (RFC 6979)
function signTransaction(transaction, privateKey) {
  // Validate transaction first
  validateTransaction(transaction);
  
  // Use library with RFC 6979 implementation
  // bitcoinjs-lib and many other libraries implement this properly
  const signature = ecdsaSign(transaction.hash, privateKey);
  return signature;
}

// INSECURE: Using random nonce generation
function signTransactionInsecure(transaction, privateKey) {
  // No validation
  const randomNonce = crypto.randomBytes(32); // Dangerous!
  const signature = ecdsaSignWithCustomNonce(transaction.hash, privateKey, randomNonce);
  return signature;
}
```

### Derivation Paths

✅ **Do:**
- Validate derivation paths before use
- Use hardened derivation for sensitive paths
- Prevent derivation of hardened paths from public keys

❌ **Don't:**
- Accept derivation paths without validation
- Use non-hardened derivation for sensitive indices
- Attempt to derive hardened paths from xpub

```javascript
// SECURE: Validate derivation path before use
function validateDerivationPath(path) {
  if (!path.startsWith('m/')) {
    throw new Error('Derivation path must start with "m/"');
  }
  
  const segments = path.slice(2).split('/');
  for (const segment of segments) {
    const hasHardened = segment.endsWith("'") || segment.endsWith("h");
    const indexStr = hasHardened ? segment.slice(0, -1) : segment;
    const index = parseInt(indexStr, 10);
    
    if (isNaN(index) || index < 0 || index >= 0x80000000) {
      throw new Error(`Invalid index in derivation path: ${segment}`);
    }
  }
  
  return true;
}

// INSECURE: No validation of derivation path
function deriveKeyInsecure(node, path) {
  // Directly using path without validation
  return node.derivePath(path); // Can throw errors or have unexpected behavior
}
```

### Browser Extension Security

✅ **Do:**
- Encrypt sensitive data before storage
- Validate origin in message handlers
- Keep private keys in the most secure context (e.g., background script)

❌ **Don't:**
- Pass private keys through messaging
- Store sensitive data in localStorage unencrypted
- Trust data from content scripts without validation

```javascript
// SECURE: Message passing without exposing private keys
// In background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'signTransaction' && sender.id === chrome.runtime.id) {
    // Retrieve key securely in background script
    getEncryptedPrivateKey(message.keyName, message.password)
      .then(privateKey => {
        // Sign in background script, never exposing the key
        const signedTx = signTransaction(message.transaction, privateKey);
        // Return only the signature
        sendResponse({ signature: signedTx });
      });
    return true; // Keep channel open for async response
  }
});

// INSECURE: Exposing private keys in messages
// In background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getPrivateKey') {
    // NEVER do this - exposes private key
    const privateKey = getPrivateKey(message.keyName);
    sendResponse({ privateKey: privateKey });
  }
});
```

### TLS Certificate Validation

✅ **Do:**
- Enforce certificate validation
- Use modern TLS versions (1.2+)
- Implement certificate pinning for critical operations

❌ **Don't:**
- Disable certificate validation (rejectUnauthorized: false)
- Accept self-signed certificates in production
- Use insecure protocols or weak cipher suites

```javascript
// SECURE: Proper TLS configuration
const secureOptions = {
  minVersion: 'TLSv1.2',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
  rejectUnauthorized: true
};

// INSECURE: Disabling certificate validation
const insecureOptions = {
  rejectUnauthorized: false // Never do this!
};
```

## 🔍 Interprocedural Analysis Tips

When analyzing your code for security issues:

1. **Trace Data Flow**
   - Follow sensitive data through function calls
   - Track how values are transformed and validated
   - Identify where security properties might be compromised

2. **Analyze Call Graphs**
   - Map dependencies between functions
   - Identify security-critical paths
   - Look for inconsistent validation across boundaries

3. **Check Error Handling**
   - Ensure errors from crypto operations are handled properly
   - Verify that failed validations prevent further processing
   - Look for places where errors might be silently ignored

## 🛠️ Recommended Tools

- **Static Analysis**: ESLint with security plugins, SonarQube
- **Dynamic Analysis**: Node.js inspector, Chrome DevTools
- **Crypto Libraries**: bitcoinjs-lib, secp256k1, noble-curves
- **Testing**: Jest with specific crypto test cases

## 🚨 Common Interprocedural Vulnerabilities

| Vulnerability | Description | Detection Approach |
|---------------|-------------|-------------------|
| Entropy Degradation | High-quality entropy source becomes compromised across function boundaries | Trace entropy sources through function calls |
| Key Leakage | Private keys exposed through return values, messages, or storage | Track key material across component boundaries |
| Validation Gaps | Security checks in one function don't properly protect another | Verify consistent validation on all paths |
| Context Crossing | Secure data moves to less secure contexts | Analyze data flow between security contexts |
| Silent Failures | Cryptographic failures handled incorrectly | Verify appropriate error handling across boundaries |

## 📝 Security Checklist

When implementing cryptographic functionality:

- [ ] Use cryptographically secure random number generators
- [ ] Implement proper key management and storage
- [ ] Validate inputs at trust boundaries
- [ ] Use deterministic signatures for ECDSA
- [ ] Keep private keys isolated in secure contexts
- [ ] Enforce TLS certificate validation
- [ ] Handle errors without exposing sensitive information
- [ ] Test with intentionally malformed inputs
- [ ] Verify cryptographic operations with known test vectors
- [ ] Conduct regular security reviews of the codebase

Remember: Security is only as strong as the weakest link in your system. Pay special attention to how security properties are maintained across function and module boundaries.