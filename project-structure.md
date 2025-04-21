# Project Structure

Below is the recommended project structure for organizing the Interprocedural Cryptographic API Misuse Dataset:

```
crypto-api-misuse-dataset/
├── .eslintrc.js                 # Main ESLint configuration
├── .eslintrc-security.js        # Security-focused ESLint rules
├── .gitignore                   # Git ignore file
├── LICENSE                      # MIT License file
├── README.md                    # Project documentation
├── package.json                 # Project metadata and dependencies
├── jest.config.js               # Jest test configuration
│
├── docs/                        # Documentation
│   ├── CRYPTO_CONCEPTS.md       # Explanation of cryptographic concepts
│   ├── KNOWN_VULNERABILITIES.md # Common vulnerability patterns
│   ├── INTERPROCEDURAL.md       # Interprocedural analysis concepts
│   └── VISUALS/                 # Diagrams and visual aids
│       ├── crypto-flow.png      # Visualization of crypto operations flow
│       └── vulnerability-patterns.png # Common vulnerability patterns
│
├── scripts/                     # Utility scripts
│   ├── run-demo.js              # Script to run examples
│   ├── run-function.js          # Script to run specific functions
│   ├── analyze-all.js           # Run all analysis scripts
│   ├── analyze-entropy.js       # Analyze entropy propagation
│   ├── analyze-key-exposure.js  # Analyze key exposure vulnerabilities
│   ├── analyze-validation.js    # Analyze validation chains
│   ├── analyze-boundaries.js    # Analyze cross-boundary data flow
│   ├── analyze-errors.js        # Analyze error propagation
│   ├── list-examples.js         # List available examples
│   └── explain-example.js       # Explain example functionality
│
├── src/                         # Source code for examples
│   ├── secure-wallet-generation.js
│   ├── insecure-wallet-generation.js
│   ├── secure-transaction-signing.js
│   ├── insecure-transaction-signing.js
│   ├── secure-browser-extension.js
│   ├── insecure-browser-extension.js
│   ├── secure-derivation-path.js
│   ├── insecure-derivation-path.js
│   ├── secure-nonce-generation.js
│   ├── insecure-nonce-generation.js
│   ├── secure-transaction-verification.js
│   ├── insecure-transaction-verification.js
│   ├── secure-ethereum-keystore.js
│   ├── insecure-ethereum-keystore.js
│   ├── secure-cross-origin.js
│   ├── insecure-cross-origin.js
│   ├── secure-random.js
│   ├── insecure-random.js
│   ├── secure-tls.js
│   ├── insecure-tls.js
│   └── index.js                 # Main exports for the package
│
├── test/                        # Test files
│   ├── secure.test.js           # Tests for secure implementations
│   ├── insecure.test.js         # Tests that verify vulnerabilities exist
│   └── mocks/                   # Test mocks and fixtures
│       └── mock-crypto.js       # Mock for crypto module in tests
│
└── tools/                       # Analysis tools
    ├── call-graph-generator.js  # Generates call graphs from examples
    ├── taint-analyzer.js        # Simple taint analysis tool
    ├── visualization/           # Visualization tools
    │   └── graph-renderer.js    # Renders call graphs with vulnerabilities
    └── rules/                   # Custom detection rules
        ├── entropy-rules.js     # Rules for entropy-related issues
        ├── key-handling-rules.js # Rules for key handling issues
        └── validation-rules.js  # Rules for validation issues
```

## Getting Started with this Structure

1. **Initial Setup**:
   ```bash
   # Clone the repository
   git clone https://github.com/your-username/crypto-api-misuse-dataset.git
   cd crypto-api-misuse-dataset
   
   # Install dependencies
   npm install
   
   # Create required directories
   mkdir -p docs/VISUALS scripts src test/mocks tools/visualization tools/rules
   ```

2. **Example Organization**:
   - Place examples in the `src/` directory
   - Follow the naming convention: `[secure|insecure]-[topic].js`

3. **Running Examples**:
   ```bash
   # Run secure wallet generation example
   npm run demo:secure wallet-generation
   
   # Run insecure transaction signing example
   npm run demo:insecure transaction-signing
   ```

4. **Analysis**:
   ```bash
   # Run all analysis on the codebase
   npm run analyze
   
   # Run specific analysis
   npm run analyze:key-exposure
   ```

5. **Testing**:
   ```bash
   # Run all tests
   npm test
   
   # Run tests for a specific pattern
   npm test -- -t "nonce generation"
   ```

## Directory Details

### scripts/

This directory contains utility scripts to help demonstrate and analyze the examples:

- `run-demo.js`: Runs and explains a specific example
- `analyze-*.js`: Scripts that perform different types of security analysis
- `list-examples.js`: Lists all available examples in the dataset
- `explain-example.js`: Provides detailed explanation of an example's functionality

### src/

Contains all the example code files, each focusing on a specific cryptographic operation:

- Secure implementations demonstrate best practices
- Insecure implementations contain deliberate vulnerabilities
- Each file is self-contained and heavily documented

### tools/

Contains analysis tools that can be used to examine the examples:

- Call graph generators
- Simple taint analysis implementations
- Visualization tools to understand data flow
- Custom detection rules for common vulnerability patterns

### docs/

Documentation that explains:

- Cryptographic concepts relevant to the examples
- Common vulnerability patterns
- Interprocedural analysis approaches
- Visual aids to understand complex flows

## Best Practices for Contributing

When adding new examples to this dataset:

1. Follow the naming convention: `[secure|insecure]-[topic].js`
2. Include comprehensive documentation about security features/vulnerabilities
3. Ensure the example demonstrates interprocedural flows
4. Add appropriate tests in the `test/` directory
5. Update analysis scripts to cover the new example type
