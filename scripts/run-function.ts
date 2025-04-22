#!/usr/bin/env ts-node

/**
 * Script to run a specific function from an example
 * 
 * Usage:
 *   ts-node run-function.ts [example-module] [function-name] [arguments...]
 */

import * as fs from 'fs';
import * as path from 'path';
import * as chalk from 'chalk';

// Check for required arguments
const args = process.argv.slice(2);
if (args.length < 2) {
  console.error(chalk.red('Usage: ts-node run-function.ts [example-module] [function-name] [arguments...]'));
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
  let modulePath: string = '';
  
  // Check if this is a direct file path or a module name
  if (exampleModule.endsWith('.js') || exampleModule.endsWith('.ts')) {
    modulePath = path.join(__dirname, '..', 'src', exampleModule);
  } else if (exampleModule.includes('-')) {
    // Try TypeScript version first, then JavaScript
    const tsPath = path.join(__dirname, '..', 'src', `${exampleModule}.ts`);
    const jsPath = path.join(__dirname, '..', 'src', `${exampleModule}.js`);
    
    if (fs.existsSync(tsPath)) {
      modulePath = tsPath;
    } else if (fs.existsSync(jsPath)) {
      modulePath = jsPath;
    } else {
      throw new Error(`Could not find module file for: ${exampleModule}`);
    }
  } else {
    // Try to load from index
    try {
      const indexPath = path.join(__dirname, '..', 'src', 'index');
      const index = require(indexPath);
      
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
      const tsPath = path.join(__dirname, '..', 'src', `${exampleModule}.ts`);
      const jsPath = path.join(__dirname, '..', 'src', `${exampleModule}.js`);
      
      if (fs.existsSync(tsPath)) {
        modulePath = tsPath;
      } else if (fs.existsSync(jsPath)) {
        modulePath = jsPath;
      } else {
        throw new Error(`Could not find module file for: ${exampleModule}`);
      }
    }
  }
  
  if (!modulePath) {
    throw new Error(`Module path could not be resolved for: ${exampleModule}`);
  }

  // Load the module
  let module: any;
  
  if (modulePath.endsWith('.ts')) {
    // For TypeScript files, we need to handle the .ts extension
    // Either using ts-node/register or by getting the compiled .js file
    try {
      require('ts-node/register');
      module = require(modulePath);
    } catch (e) {
      // Try to find the compiled .js file
      const jsPath = modulePath.replace(/\.ts$/, '.js');
      module = require(jsPath);
    }
  } else {
    // For JavaScript files
    module = require(modulePath);
  }
  
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
  console.error(chalk.red(`Failed to load module '${exampleModule}': ${(error as Error).message}`));
  
  // List available modules
  try {
    const srcDir = path.join(__dirname, '..', 'src');
    const files = fs.readdirSync(srcDir)
      .filter(file => file.endsWith('.js') || file.endsWith('.ts'));
    
    console.log(chalk.yellow('Available modules:'));
    files.forEach(file => {
      console.log(chalk.yellow(`  ${file.replace(/\.(js|ts)$/, '')}`));
    });
  } catch (e) {
    console.error(chalk.red(`Failed to list available modules: ${(e as Error).message}`));
  }
  
  process.exit(1);
}

function executeFunction(func: Function, args: any[], funcName: string, moduleName: string): void {
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
    console.log(chalk.red(`Execution failed: ${(error as Error).message}`));
    console.log(chalk.red((error as Error).stack || ''));
  }
}