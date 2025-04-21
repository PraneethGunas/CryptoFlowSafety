#!/usr/bin/env node

/**
 * Script to list all available secure and insecure examples
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

const srcDir = path.join(__dirname, '..', 'src');
const files = fs.readdirSync(srcDir);

console.log(chalk.bold.cyan('Available Crypto API Examples:'));
console.log(chalk.yellow('==========================='));

// List secure examples
console.log(chalk.green.bold('\nSecure Implementations:'));
const secureExamples = files.filter(file => file.startsWith('secure-') && file.endsWith('.js'));
secureExamples.forEach(file => {
  const exampleName = file.replace('secure-', '').replace('.js', '');
  console.log(chalk.green(`- ${exampleName}`));
});

// List insecure examples
console.log(chalk.red.bold('\nInsecure Implementations:'));
const insecureExamples = files.filter(file => file.startsWith('insecure-') && file.endsWith('.js'));
insecureExamples.forEach(file => {
  const exampleName = file.replace('insecure-', '').replace('.js', '');
  console.log(chalk.red(`- ${exampleName}`));
});

console.log(chalk.yellow('\n==========================='));
console.log(chalk.cyan.bold('Usage instructions:'));
console.log(chalk.white('  npm run demo:secure <example-name>    # Run a secure example'));
console.log(chalk.white('  npm run demo:insecure <example-name>  # Run an insecure example'));
console.log(chalk.white('  npm run demo:function <function-name> # Run a specific function'));
