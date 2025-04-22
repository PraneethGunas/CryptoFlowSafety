/**
 * Insecure implementation of cross-origin communication with cryptography
 * 
 * Security issues:
 * - Insufficient origin validation
 * - No message authentication
 * - Poor key handling
 * - Interprocedural weakness in message validation and handling
 */

// Note: This is a browser-specific implementation that uses
// browser APIs. These would not work in a standard Node.js environment.

import { ExtendedWindow, InsecureMessage, InsecureMessageEnvelope } from './types/browser';

// Declare global window type
declare const window: ExtendedWindow;

// Global variable to store sensitive data (INSECURE)
let sensitiveData: any = null;

interface CommunicationResult {
  sendMessage: (message: any) => void;
}

interface SigningRequest {
  action: string;
  privateKey: string;
  message: string;
}

interface SignatureResult {
  action: string;
  signature: string;
  message: string;
}

// Function 1: Setup insecure communication channel (INSECURE)
export function setupInsecureCommunication(iframe: HTMLIFrameElement): HTMLIFrameElement {
  // VULNERABILITY: No secure key generation
  // VULNERABILITY: No origin validation stored
  
  // Setup message listener
  window.addEventListener('message', (event: MessageEvent) => {
    // VULNERABILITY: No origin validation
    // This allows any website to send messages
    
    // VULNERABILITY: No source validation
    // This allows any window to impersonate the iframe
    
    // Process the message
    processInsecureMessage(event.data);
  });
  
  return iframe;
}

// Function 2: Send insecure message to iframe (INSECURE)
export function sendInsecureMessage(message: any, iframe: HTMLIFrameElement): void {
  // VULNERABILITY: No message authentication
  
  // VULNERABILITY: No origin restriction
  // Using '*' allows any origin to receive the message
  iframe.contentWindow?.postMessage({
    data: JSON.stringify(message)
  }, '*');
}

// Function 3: Process insecure message from iframe (INSECURE)
export function processInsecureMessage(data: InsecureMessageEnvelope): void {
  // VULNERABILITY: Minimal message validation
  if (!data || !data.data) {
    console.error('Invalid message format');
    return;
  }
  
  // VULNERABILITY: No message authentication
  
  // Parse the message
  try {
    const parsedData = JSON.parse(data.data);
    
    // VULNERABILITY: Storing sensitive data in a global variable
    sensitiveData = parsedData;
    
    // Process the message
    console.log('Received message:', parsedData);
    
    // VULNERABILITY: Executing data from the message
    if (parsedData.action === 'eval') {
      // SEVERE VULNERABILITY: Evaluating code from messages
      eval(parsedData.code);
    }
  } catch (error) {
    console.error('Failed to parse message:', error);
  }
}

// Function 4: Handle private key signing request (INSECURE)
export function handleSigningRequest(data: SigningRequest): string | null {
  // VULNERABILITY: No validation of the request origin
  
  if (data.action === 'sign' && data.privateKey && data.message) {
    // VULNERABILITY: Accepting a private key through messaging
    const privateKey = data.privateKey;
    const message = data.message;
    
    // Perform signing
    const signature = signWithPrivateKey(privateKey, message);
    
    // VULNERABILITY: Sending the signature to an unvalidated origin
    window.parent.postMessage({
      action: 'signatureResult',
      signature,
      message
    }, '*');
    
    return signature;
  }
  
  return null;
}

// Helper function to sign with private key (mock implementation)
export function signWithPrivateKey(privateKey: string, message: string): string {
  // This would be a real signing implementation in a production environment
  // For this example, we're just creating a mock signature
  return `signature-for-${message}-with-key-${privateKey.slice(0, 8)}`;
}

// Main function to initialize insecure cross-origin communication
export function insecureIframeCommunication(iframeUrl: string): CommunicationResult {
  // Create an iframe
  const iframe = document.createElement('iframe');
  iframe.src = iframeUrl;
  document.body.appendChild(iframe);
  
  // Setup insecure communication
  setupInsecureCommunication(iframe);
  
  // Return an object for sending messages
  return {
    sendMessage: (message: any) => sendInsecureMessage(message, iframe)
  };
}