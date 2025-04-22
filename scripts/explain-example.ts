#!/usr/bin/env ts-node

/**
 * Script to explain the differences between secure and insecure implementations
 */

import * as fs from 'fs';
import * as path from 'path';
import * as chalk from 'chalk';

// Check for required arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.error(chalk.red('Usage: ts-node explain-example.ts [example-name]'));
  process.exit(1);
}

const exampleName = args[0];
const secureFilePath = path.join(__dirname, '..', 'src', `secure-${exampleName}.ts`);
const insecureFilePath = path.join(__dirname, '..', 'src', `insecure-${exampleName}.ts`);
const secureJsFilePath = path.join(__dirname, '..', 'src', `secure-${exampleName}.js`);
const insecureJsFilePath = path.join(__dirname, '..', 'src', `insecure-${exampleName}.js`);

// Determine which files exist
let secureContent: string;
let insecureContent: string;

if (fs.existsSync(secureFilePath)) {
  secureContent = fs.readFileSync(secureFilePath, 'utf8');
} else if (fs.existsSync(secureJsFilePath)) {
  secureContent = fs.readFileSync(secureJsFilePath, 'utf8');
} else {
  console.error(chalk.red(`Secure example not found for: ${exampleName}`));
  listAvailableExamples();
  process.exit(1);
}

if (fs.existsSync(insecureFilePath)) {
  insecureContent = fs.readFileSync(insecureFilePath, 'utf8');
} else if (fs.existsSync(insecureJsFilePath)) {
  insecureContent = fs.readFileSync(insecureJsFilePath, 'utf8');
} else {
  console.error(chalk.red(`Insecure example not found for: ${exampleName}`));
  listAvailableExamples();
  process.exit(1);
}

// Display header
console.log(chalk.bold.cyan(`\nExplanation of ${exampleName} implementations\n`));
console.log(chalk.yellow('=================================================='));

// Extract and display information from the secure file
const secureHeaderComment = extractHeaderComment(secureContent);
const secureFeatures = extractSecurityFeatures(secureContent);

console.log(chalk.green.bold('\nSecure Implementation:'));
console.log(chalk.green(secureHeaderComment));
console.log(chalk.green.bold('\nSecurity Features:'));
secureFeatures.forEach(feature => {
  console.log(chalk.green(`✓ ${feature}`));
});

// Extract and display information from the insecure file
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
const secureFunctionNames = extractFunctionNames(secureContent);
const insecureFunctionNames = extractFunctionNames(insecureContent);

// Map corresponding functions
for (let i = 0; i < secureFunctionNames.length && i < insecureFunctionNames.length; i++) {
  console.log(chalk.cyan(`\nFunction ${i + 1}:`));
  console.log(chalk.green(`  Secure: ${secureFunctionNames[i]}`));
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
function extractHeaderComment(code: string): string {
  const headerRegex = /\/\*\*[\s\S]*?\*\//;
  const match = code.match(headerRegex);
  
  if (match) {
    return match[0]
      .replace(/\/\*\*|\*\//g, '')
      .replace(/^\s*\*\s?/gm, '')
      .trim();
  }
  
  return "No header comment found.";
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
  
  return ["No security features listed."];
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
  
  return ["No vulnerabilities listed."];
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

// Helper function to list available examples
function listAvailableExamples(): void {
  console.log(chalk.yellow('Available examples:'));
  
  // List available examples
  const srcDir = path.join(__dirname, '..', 'src');
  const files = fs.readdirSync(srcDir)
    .filter(file => 
      (file.startsWith('secure-') && (file.endsWith('.js') || file.endsWith('.ts')))
    );
  
  files.forEach(file => {
    console.log(chalk.yellow(`  ${file.replace('secure-', '').replace(/\.(js|ts)$/, '')}`));
  });
}