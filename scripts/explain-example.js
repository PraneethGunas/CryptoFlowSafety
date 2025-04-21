#!/usr/bin/env node

/**
 * Script to explain the differences between secure and insecure implementations
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

// Check for required arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.error(chalk.red('Usage: node explain-example.js [example-name]'));
  process.exit(1);
}

const exampleName = args[0];
const secureFilePath = path.join(__dirname, '..', 'src', `secure-${exampleName}.js`);
const insecureFilePath = path.join(__dirname, '..', 'src', `insecure-${exampleName}.js`);

// Check if files exist
if (!fs.existsSync(secureFilePath) || !fs.existsSync(insecureFilePath)) {
  console.error(chalk.red(`Example files not found for: ${exampleName}`));
  console.log(chalk.yellow('Available examples:'));
  
  // List available examples
  const srcDir = path.join(__dirname, '..', 'src');
  const files = fs.readdirSync(srcDir)
    .filter(file => file.startsWith('secure-') && file.endsWith('.js'));
  
  files.forEach(file => {
    console.log(chalk.yellow(`  ${file.replace('secure-', '').replace('.js', '')}`));
  });
  
  process.exit(1);
}

// Display header
console.log(chalk.bold.cyan(`\nExplanation of ${exampleName} implementations\n`));
console.log(chalk.yellow('=================================================='));

// Extract and display information from the secure file
const secureContent = fs.readFileSync(secureFilePath, 'utf8');
const secureHeaderComment = extractHeaderComment(secureContent);
const secureFeatures = extractSecurityFeatures(secureContent);

console.log(chalk.green.bold('\nSecure Implementation:'));
console.log(chalk.green(secureHeaderComment));
console.log(chalk.green.bold('\nSecurity Features:'));
secureFeatures.forEach(feature => {
  console.log(chalk.green(`✓ ${feature}`));
});

// Extract and display information from the insecure file
const insecureContent = fs.readFileSync(insecureFilePath, 'utf8');
const insecureHeaderComment = extractHeaderComment(insecureContent);
const vulnerabilities = extractVulnerabilities(insecureContent);

console.log(chalk.red.bold('\nInsecure Implementation:'));
console.log(chalk.red(insecureHeaderComment));
console.log(chalk.red.bold('\nVulnerabilities:'));
vulnerabilities.forEach(vulnerability => {
  console.log(chalk.red(`✗ ${vulnerability}`));
});

// Display key differences
console.log(chalk.cyan.bold('\nKey Differences:'));
const functionNames = extractFunctionNames(secureContent);
const insecureFunctionNames = extractFunctionNames(insecureContent);

// Map corresponding functions
for (let i = 0; i < functionNames.length && i < insecureFunctionNames.length; i++) {
  console.log(chalk.cyan(`\nFunction ${i + 1}:`));
  console.log(chalk.green(`  Secure: ${functionNames[i]}`));
  console.log(chalk.red(`  Insecure: ${insecureFunctionNames[i]}`));
}

console.log(chalk.yellow('\n=================================================='));
console.log(chalk.cyan.bold('Recommendations:'));
console.log(chalk.white('  1. Always use cryptographically secure random number generators'));
console.log(chalk.white('  2. Follow secure cryptographic patterns and best practices'));
console.log(chalk.white('  3. Be aware of how security properties propagate across function boundaries'));
console.log(chalk.white('  4. Use established and well-tested cryptographic libraries'));
console.log(chalk.white('  5. Validate inputs and outputs at trust boundaries'));

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
