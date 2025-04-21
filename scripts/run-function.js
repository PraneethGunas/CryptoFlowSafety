#!/usr/bin/env node

/**
 * Script to run a specific function from an example
 * 
 * Usage:
 *   node run-function.js [example-module] [function-name] [arguments...]
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

// Check for required arguments
const args = process.argv.slice(2);
if (args.length < 2) {
  console.error(chalk.red('Usage: node run-function.js [example-module] [function-name] [arguments...]'));
  process.exit(1);
}

const exampleModule = args[0];
const functionName = args[1];
const functionArgs = args.slice(2).map(arg => {
  try {
    // Try to parse as JSON for complex arguments
    return JSON.parse(arg);
  } catch (e) {
    // Otherwise use as string
    return arg;
  }
});

// Load the module
try {
  let modulePath;
  
  // Check if this is a direct file path or a module name
  if (exampleModule.endsWith('.js')) {
    modulePath = path.join(__dirname, '..', 'src', exampleModule);
  } else if (exampleModule.includes('-')) {
    modulePath = path.join(__dirname, '..', 'src', `${exampleModule}.js`);
  } else {
    // Try to load from index
    try {
      const index = require(path.join(__dirname, '..', 'src', 'index.js'));
      
      if (exampleModule in index) {
        // Execute function from the index export
        if (functionName in index[exampleModule]) {
          executeFunction(index[exampleModule][functionName], functionArgs, functionName, exampleModule);
        } else {
          console.error(chalk.red(`Function '${functionName}' not found in module '${exampleModule}'`));
          console.log(chalk.yellow('Available functions:'));
          Object.keys(index[exampleModule]).forEach(func => {
            console.log(chalk.yellow(`  ${func}`));
          });
          process.exit(1);
        }
        process.exit(0);
      }
    } catch (e) {
      // Fall back to direct module loading
      modulePath = path.join(__dirname, '..', 'src', `${exampleModule}.js`);
    }
  }
  
  // Load the module
  const module = require(modulePath);
  
  // Check if the function exists
  if (functionName in module) {
    executeFunction(module[functionName], functionArgs, functionName, exampleModule);
  } else {
    console.error(chalk.red(`Function '${functionName}' not found in module '${exampleModule}'`));
    console.log(chalk.yellow('Available functions:'));
    Object.keys(module).forEach(func => {
      console.log(chalk.yellow(`  ${func}`));
    });
    process.exit(1);
  }
} catch (error) {
  console.error(chalk.red(`Failed to load module '${exampleModule}': ${error.message}`));
  
  // List available modules
  try {
    const srcDir = path.join(__dirname, '..', 'src');
    const files = fs.readdirSync(srcDir)
      .filter(file => file.endsWith('.js'));
    
    console.log(chalk.yellow('Available modules:'));
    files.forEach(file => {
      console.log(chalk.yellow(`  ${file.replace('.js', '')}`));
    });
  } catch (e) {
    console.error(chalk.red(`Failed to list available modules: ${e.message}`));
  }
  
  process.exit(1);
}

function executeFunction(func, args, funcName, moduleName) {
  console.log(chalk.cyan.bold(`\nExecuting function '${funcName}' from '${moduleName}'\n`));
  console.log(chalk.yellow('Arguments:'));
  
  if (args.length === 0) {
    console.log(chalk.yellow('  No arguments provided'));
  } else {
    args.forEach((arg, i) => {
      console.log(chalk.yellow(`  Arg ${i + 1}: ${JSON.stringify(arg)}`));
    });
  }
  
  console.log(chalk.yellow('\nExecution result:'));
  
  try {
    const result = func(...args);
    console.log(result);
    
    // Add some type information
    console.log(chalk.gray(`\nResult type: ${typeof result}`));
    if (typeof result === 'object' && result !== null) {
      console.log(chalk.gray(`Object properties: ${Object.keys(result).join(', ')}`));
    }
    
    console.log(chalk.green('\nExecution successful!'));
  } catch (error) {
    console.log(chalk.red(`Execution failed: ${error.message}`));
    console.log(chalk.red(error.stack));
  }
}