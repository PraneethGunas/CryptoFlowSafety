# Installation and Usage Guide

This guide will help you set up and use the Interprocedural Cryptographic API Misuse Dataset for research, education, or analysis purposes.

## Prerequisites

Before installing, ensure you have the following:

- Node.js (v14.0.0 or higher)
- npm (v6.0.0 or higher)
- Git

## Installation

### Option 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/your-username/crypto-api-misuse-dataset.git

# Navigate to the project directory
cd crypto-api-misuse-dataset

# Install dependencies
npm install
```

### Option 2: Install as a Package

```bash
# Install directly from GitHub
npm install github:your-username/crypto-api-misuse-dataset

# Or once published to npm
npm install crypto-api-misuse-dataset
```

## Project Structure

After installation, you should have the following structure:

```
crypto-api-misuse-dataset/
├── src/                  # Source code examples
├── scripts/              # Utility scripts
├── test/                 # Test files
├── tools/                # Analysis tools
├── docs/                 # Documentation
└── package.json          # Project metadata
```

## Usage

### Running Examples

The dataset includes utility scripts to demonstrate both secure and insecure implementations:

```bash
# Run a secure example
npm run demo:secure wallet-generation

# Run an insecure example
npm run demo:insecure transaction-signing

# Run a specific function from an example
npm run demo:function secure-wallet-generation generateSecureEntropy
```

### Viewing Examples

You can examine the examples directly in the `src/` directory. Each example is well-documented with comments explaining the security properties or vulnerabilities.

### Running Analysis

The project includes several analysis scripts to detect potential vulnerabilities:

```bash
# Run all analysis scripts
npm run analyze

# Run specific analysis
npm run analyze:entropy-propagation
npm run analyze:key-exposure
```

### Running Tests

Tests validate that secure examples work correctly and that insecure examples exhibit the expected vulnerabilities:

```bash
# Run all tests
npm test

# Run tests for specific examples
npm test -- -t "nonce generation"
```

## Example Workflows

### Educational Use

1. **Learning About Secure Implementations**:
   ```bash
   # View a list of all secure examples
   npm run examples:list -- secure
   
   # Run a secure example with explanation
   npm run demo:secure wallet-generation
   
   # Explore the code directly
   cat src/secure-wallet-generation.js
   ```

2. **Understanding Vulnerabilities**:
   ```bash
   # Run an insecure example with vulnerability explanations
   npm run demo:insecure transaction-signing
   
   # Compare secure and insecure implementations
   npm run examples:explain wallet-generation
   ```

### Research Use

1. **Analyzing Interprocedural Patterns**:
   ```bash
   # Generate call graphs for all examples
   node tools/call-graph-generator.js
   
   # Visualize security-critical paths
   node tools/visualization/graph-renderer.js
   ```

2. **Evaluating Analysis Tools**:
   ```bash
   # Run a custom analysis tool against the dataset
   node tools/taint-analyzer.js src/insecure-wallet-generation.js
   
   # Compare results with known vulnerabilities
   npm run analyze:entropy-propagation
   ```

3. **Extending the Dataset**:
   ```bash
   # Create a new example pair
   cp src/secure-wallet-generation.js src/secure-my-example.js
   cp src/insecure-wallet-generation.js src/insecure-my-example.js
   
   # Edit the files to demonstrate new patterns
   # Add tests for the new examples
   touch test/my-example.test.js
   ```

## Troubleshooting

### Common Issues

1. **Dependency Errors**:
   ```bash
   # Ensure you have the correct Node.js version
   node -v
   
   # Clear npm cache and reinstall
   npm cache clean --force
   npm install
   ```

2. **Script Execution Errors**:
   ```bash
   # Make scripts executable
   chmod +x scripts/*.js
   
   # Run with explicit node command
   node scripts/run-demo.js secure wallet-generation
   ```

3. **Test Failures**:
   ```bash
   # Run tests in verbose mode
   npm test -- --verbose
   
   # Check for library compatibility issues
   npm ls
   ```

## Advanced Usage

### Creating Custom Analysis Rules

You can create custom analysis rules to detect specific patterns:

1. Create a new rule file in `tools/rules/`:
   ```bash
   touch tools/rules/my-custom-rule.js
   ```

2. Implement your rule following the template format:
   ```javascript
   module.exports = {
     name: 'my-custom-rule',
     description: 'Detects a specific vulnerability pattern',
     detect: function(ast, filename) {
       // Analysis logic here
       return {
         vulnerabilities: [],
         warnings: []
       };
     }
   };
   ```

3. Register your rule in `tools/rules/index.js`

4. Run your custom analysis:
   ```bash
   node tools/run-custom-analysis.js my-custom-rule
   ```

### Generating Visual Reports

The dataset includes tools to generate visual reports of vulnerabilities:

```bash
# Generate HTML report
node tools/generate-report.js --format html --output report.html

# Generate JSON report
node tools/generate-report.js --format json --output report.json

# Generate visualization of interprocedural flows
node tools/visualization/flow-visualizer.js --example wallet-generation
```

## Contributing

We welcome contributions to expand and improve the dataset:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-example`)
3. Commit your changes (`git commit -m 'Add new example for XYZ'`)
4. Push to the branch (`git push origin feature/new-example`)
5. Open a Pull Request

Please ensure your contributions follow the project's coding style and include appropriate documentation and tests.

## Additional Resources

- **Documentation**: See the `docs/` directory for detailed documentation
- **Examples**: Browse all examples in the `src/` directory
- **Analysis Tools**: Explore available tools in the `tools/` directory
- **Tests**: View test cases in the `test/` directory

## License

This project is licensed under the MIT License - see the LICENSE file for details.
