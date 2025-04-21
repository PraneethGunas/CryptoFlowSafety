#!/usr/bin/env node

/**
 * Script to run and demonstrate secure or insecure examples
 * 
 * Usage:
 *   npm run demo:secure wallet-generation
 *   npm run demo:insecure transaction-signing
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

// Check for required arguments
const args = process.argv.slice(2);
if (args.length < 2) {
  console.error(chalk.red('Usage: node run-demo.js [secure|insecure] [example-name]'));
  process.exit(1);
}

const securityType = args[0];
const exampleName = args[1];

// Validate security type
if (securityType !== 'secure' && securityType !== 'insecure') {
  console.error(chalk.red('Security type must be "secure" or "insecure"'));
  process.exit(1);
}

const fileName = `${securityType}-${exampleName}.js`;
const filePath = path.join(__dirname, 'src', fileName);

// Check if file exists
if (!fs.existsSync(filePath)) {
  console.error(chalk.red(`Example file not found: ${fileName}`));
  console.log(chalk.yellow('Available examples:'));
  
  // List available examples
  const srcDir = path.join(__dirname, 'src');
  const files = fs.readdirSync(srcDir)
    .filter(file => file.startsWith(securityType) && file.endsWith('.js'));
  
  files.forEach(file => {
    console.log(chalk.yellow(`  ${file.replace(`${securityType}-`, '').replace('.js', '')}`));
  });
  
  process.exit(1);
}

// Display header
console.log(chalk.bold.underline(`\nDemonstrating ${securityType} example: ${exampleName}\n`));

// Read and parse the file content
const fileContent = fs.readFileSync(filePath, 'utf8');
const functionNames = extractFunctionNames(fileContent);

// Display file structure
console.log(chalk.cyan('Example Structure:'));
functionNames.forEach((func, i) => {
  console.log(chalk.cyan(`${i + 1}. ${func}`));
});
console.log();

// Extract and display the file header comment if it exists
const headerComment = extractHeaderComment(fileContent);
if (headerComment) {
  console.log(chalk.magenta('Description:'));
  console.log(headerComment);
  console.log();
}

// Execute the example
console.log(chalk.green('Executing example...'));
console.log(chalk.yellow('-------------------------------------------'));

try {
  // Require the file and look for a main function to execute
  const example = require(filePath);
  
  // Find a main function to execute
  const mainFunctionName = functionNames.find(name => 
    name.toLowerCase().includes('main') || 
    name.startsWith(securityType)
  );
  
  if (mainFunctionName && typeof example[mainFunctionName] === 'function') {
    // Create some dummy data for the example
    const dummyData = createDummyData(exampleName);
    
    // Execute the main function with dummy data
    const result = example[mainFunctionName](dummyData);
    
    // Display the result
    console.log(chalk.yellow('\nExecution result:'));
    console.log(result);
  } else {
    console.log(chalk.yellow('No main function found to execute. This is just a library file.'));
    console.log(chalk.yellow('Review the code to understand the example.'));
  }
} catch (error) {
  if (securityType === 'insecure') {
    console.log(chalk.red('\nExecution failed (expected for insecure examples):'));
    console.log(chalk.red(error.message));
    console.log(chalk.yellow('\nThis demonstrates why the insecure implementation is problematic.'));
  } else {
    console.log(chalk.red('\nExecution failed:'));
    console.log(chalk.red(error.stack));
  }
}

console.log(chalk.yellow('-------------------------------------------'));

// Show security implications
if (securityType === 'secure') {
  console.log(chalk.green('\nSecurity features demonstrated:'));
  const securityFeatures = extractSecurityFeatures(fileContent);
  securityFeatures.forEach(feature => {
    console.log(chalk.green(`✓ ${feature}`));
  });
} else {
  console.log(chalk.red('\nVulnerabilities demonstrated:'));
  const vulnerabilities = extractVulnerabilities(fileContent);
  vulnerabilities.forEach(vulnerability => {
    console.log(chalk.red(`✗ ${vulnerability}`));
  });
}

console.log(chalk.bold('\nRecommendation:'));
if (securityType === 'secure') {
  console.log(chalk.green('✓ This implementation follows security best practices.'));
  console.log(chalk.green('✓ Review the code comments to understand the security features.'));
} else {
  console.log(chalk.red('✗ This implementation contains deliberate vulnerabilities.'));
  console.log(chalk.red('✗ DO NOT use this code in production environments.'));
  console.log(chalk.yellow('➜ Check the secure version for the correct implementation.'));
}

// Helper function to extract function names from code
function extractFunctionNames(code) {
  const functionRegex = /function\s+([a-zA-Z0-9_]+)\s*\(/g;
  const functionNames = [];
  let match;
  
  while ((match = functionRegex.exec(code)) !== null) {
    functionNames.push(match[1]);
  }
  
  return functionNames;
}

// Helper function to extract header comment
function extractHeaderComment(code) {
  const headerRegex = /\/\*\*[\s\S]*?\*\//;
  const match = code.match(headerRegex);
  
  if (match) {
    return match[0]
      .replace(/\/\*\*|\*\//g, '')
      .replace(/^\s*\*\s?/gm, '')
      .trim();
  }
  
  return null;
}

// Helper function to extract security features
function extractSecurityFeatures(code) {
  const featuresRegex = /Key security features:([\s\S]*?)(?:\*\/|\n\s*\n)/;
  const match = code.match(featuresRegex);
  
  if (match) {
    return match[1]
      .split('-')
      .slice(1)
      .map(feature => feature.trim())
      .filter(Boolean);
  }
  
  return [];
}

// Helper function to extract vulnerabilities
function extractVulnerabilities(code) {
  const vulnerabilitiesRegex = /Security issues:([\s\S]*?)(?:\*\/|\n\s*\n)/;
  const match = code.match(vulnerabilitiesRegex);
  
  if (match) {
    return match[1]
      .split('-')
      .slice(1)
      .map(vulnerability => vulnerability.trim())
      .filter(Boolean);
  }
  
  return [];
}

// Create dummy data based on the example type
function createDummyData(exampleName) {
  switch (exampleName) {
    case 'wallet-generation':
      return 'strongpassphrase123';
    case 'transaction-signing':
      return {
        seed: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        derivationPath: "m/44'/0'/0'/0/0",
        utxos: [{ txid: 'abcd1234', vout: 0, value: 100000 }],
        recipients: [{ address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', value: 50000 }],
        fee: 1000,
        changeAddress: '1ChangeAddressDummyXXXXXXXXXX'
      };
    case 'browser-extension':
      return {
        privateKey: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        password: 'strongpassphrase123',
        keyName: 'myKey'
      };
    case 'derivation-path':
      return {
        seed: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        path: "m/44'/0'/0'/0/0"
      };
    case 'nonce-generation':
      return {
        privateKey: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        message: 'Hello, world!'
      };
    case 'transaction-verification':
      return {
        transaction: {
          inputs: [{ txid: 'abcd1234', vout: 0 }],
          outputs: [{ address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', value: 50000 }]
        },
        privateKey: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      };
    case 'ethereum-keystore':
      return 'strongpassphrase123';
    case 'cross-origin':
      return 'https://example.com';
    case 'random':
      return 'data to encrypt';
    case 'tls':
      return 'https://example.com';
    default:
      return 'dummy data';
  }
}