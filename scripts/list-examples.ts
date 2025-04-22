#!/usr/bin/env ts-node

/**
 * Script to list all available secure and insecure examples
 */

import * as fs from 'fs';
import * as path from 'path';
import * as chalk from 'chalk';

const srcDir = path.join(__dirname, '..', 'src');
const files = fs.readdirSync(srcDir);

console.log(chalk.bold.cyan('Available Crypto API Examples:'));
console.log(chalk.yellow('==========================='));

// List secure examples
console.log(chalk.green.bold('\nSecure Implementations:'));
const secureExamples = files.filter(file => 
  (file.startsWith('secure-') && file.endsWith('.js')) || 
  (file.startsWith('secure-') && file.endsWith('.ts'))
);

secureExamples.forEach(file => {
  const exampleName = file.replace('secure-', '').replace(/\.(js|ts)$/, '');
  console.log(chalk.green(`- ${exampleName}`));
});

// List insecure examples
console.log(chalk.red.bold('\nInsecure Implementations:'));
const insecureExamples = files.filter(file => 
  (file.startsWith('insecure-') && file.endsWith('.js')) || 
  (file.startsWith('insecure-') && file.endsWith('.ts'))
);

insecureExamples.forEach(file => {
  const exampleName = file.replace('insecure-', '').replace(/\.(js|ts)$/, '');
  console.log(chalk.red(`- ${exampleName}`));
});

console.log(chalk.yellow('\n==========================='));
console.log(chalk.cyan.bold('Usage instructions:'));
console.log(chalk.white('  npm run demo:secure <example-name>    # Run a secure example'));
console.log(chalk.white('  npm run demo:insecure <example-name>  # Run an insecure example'));
console.log(chalk.white('  npm run demo:function <function-name> # Run a specific function'));