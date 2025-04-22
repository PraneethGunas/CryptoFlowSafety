#!/usr/bin/env ts-node

/**
 * Script to run and demonstrate secure or insecure examples
 * 
 * Usage:
 *   npm run demo:secure wallet-generation
 *   npm run demo:insecure transaction-signing
 */

import * as fs from 'fs';
import * as path from 'path';
import * as chalk from 'chalk';

// Check for required arguments
const args = process.argv.slice(2);
if (args.length < 2) {
  console.error(chalk.red('Usage: ts-node run-demo-script.ts [secure|insecure] [example-name]'));
  process.exit(1);
}

const securityType = args[0];
const exampleName = args[1];

// Validate security type
if (securityType !== 'secure' && securityType !== 'insecure') {
  console.error(chalk.red('Security type must be "secure" or "insecure"'));
  process.exit(1);
}

const fileName = `${securityType}-${exampleName}.ts`;
const filePath = path.join(__dirname, 'src', fileName);
const jsFilePath = path.join(__dirname, 'src', `${securityType}-${exampleName}.js`);

// Check if file exists (try TypeScript first, then JavaScript)
let fileContent: string;
let actualFilePath: string;

if (fs.existsSync(filePath)) {
  fileContent = fs.readFileSync(filePath, 'utf8');
  actualFilePath = filePath;
} else if (fs.existsSync(jsFilePath)) {
  fileContent = fs.readFileSync(jsFilePath, 'utf8');
  actualFilePath = jsFilePath;
} else {
  console.error(chalk.red(`Example file not found: ${fileName}`));
  console.log(chalk.yellow('Available examples:'));
  
  // List available examples
  const srcDir = path.join(__dirname, 'src');
  const files = fs.readdirSync(srcDir)
    .filter(file => file.startsWith(securityType) && (file.endsWith('.js') || file.endsWith('.ts')));
  
  files.forEach(file => {
    console.log(chalk.yellow(`  ${file.replace(`${securityType}-`, '').replace(/\.(js|ts)$/, '')}`));
  });
  
  process.exit(1);
}

// Display header
console.log(chalk.bold.underline(`\nDemonstrating ${securityType} example: ${exampleName}\n`));

// Read and parse the file content
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
  let module: any;
  if (actualFilePath.endsWith('.ts')) {
    // For TypeScript files
    module = require(actualFilePath.replace(/\.ts$/, ''));
  } else {
    // For JavaScript files
    module = require(actualFilePath);
  }
  
  // Find a main function to execute
  const mainFunctionName = functionNames.find(name => 
    name.toLowerCase().includes('main') || 
    name.startsWith(securityType)
  );
  
  if (mainFunctionName && typeof module[mainFunctionName] === 'function') {
    // Create some dummy data for the example
    const dummyData = createDummyData(exampleName);
    
    // Execute the main function with dummy data
    const result = module[mainFunctionName](dummyData);
    
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
    console.log(chalk.red((error as Error).message));
    console.log(chalk.yellow('\nThis demonstrates why the insecure implementation is problematic.'));
  } else {
    console.log(chalk.red('\nExecution failed:'));
    console.log(chalk.red((error as Error).stack || (error as Error).message));
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
function extractFunctionNames(code: string): string[] {
  // Updated regex to handle both JavaScript and TypeScript function declarations
  const functionRegex = /(?:function|export\s+function)\s+([a-zA-Z0-9_]+)\s*\(/g;
  const functionNames: string[] = [];
  let match: RegExpExecArray | null;
  
  while ((match = functionRegex.exec(code)) !== null) {
    functionNames.push(match[1]);
  }
  
  return functionNames;
}

// Helper function to extract header comment
function extractHeaderComment(code: string): string | null {
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
function extractSecurityFeatures(code: string): string[] {
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
function extractVulnerabilities(code: string): string[] {
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
function createDummyData(exampleName: string): any {
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