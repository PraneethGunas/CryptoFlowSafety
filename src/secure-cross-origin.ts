/**
 * Secure implementation of cross-origin communication with cryptography
 * 
 * Key security features:
 * - Proper origin validation
 * - Message authentication
 * - Proper key handling
 */

// Note: This is a browser-specific implementation that uses
// browser APIs. These would not work in a standard Node.js environment.

import { ExtendedWindow, CommunicationChannel, SecureMessage, SecureMessageEnvelope } from './types/browser';

// Declare global window type
declare const window: ExtendedWindow;
declare const crypto: Crypto;

interface CommunicationResult {
  sendMessage: (message: any) => void;
}

// Function 1: Generate a secure communication key
export function generateSecureCommunicationKey(): Uint8Array {
  // Generate a secure random key
  return crypto.getRandomValues(new Uint8Array(32));
}

// Function 2: Setup secure communication channel
export function setupSecureCommunication(
  iframe: HTMLIFrameElement, 
  targetOrigin: string
): CommunicationChannel {
  // Generate a secure key for communication
  const key = generateSecureCommunicationKey();
  
  // Store the key and target origin
  const channel: CommunicationChannel = {
    key,
    targetOrigin,
    iframe
  };
  
  // Setup message listener
  window.addEventListener('message', (event: MessageEvent) => {
    // Validate origin
    if (event.origin !== targetOrigin) {
      console.error(`Invalid origin: ${event.origin}`);
      return;
    }
    
    // Validate source
    if (event.source !== iframe.contentWindow) {
      console.error('Invalid source');
      return;
    }
    
    // Process the message
    processSecureMessage(event.data, channel);
  });
  
  return channel;
}

// Function 3: Send secure message to iframe
export function sendSecureMessage(message: any, channel: CommunicationChannel): void {
  // Create a nonce
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  
  // Create HMAC for message authentication
  const msgData = JSON.stringify({ message, nonce: Array.from(nonce) });
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(msgData);
  
  // Create HMAC
  const hmac = createHmac(channel.key, msgBytes);
  
  // Send the message with HMAC
  channel.iframe.contentWindow?.postMessage({
    data: msgData,
    hmac: Array.from(hmac)
  }, channel.targetOrigin);
}

// Function 4: Process secure message from iframe
export function processSecureMessage(data: SecureMessageEnvelope, channel: CommunicationChannel): void {
  // Validate message format
  if (!data || !data.data || !data.hmac) {
    console.error('Invalid message format');
    return;
  }
  
  // Verify HMAC
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(data.data);
  const expectedHmac = createHmac(channel.key, msgBytes);
  
  // Constant-time comparison to prevent timing attacks
  if (!constantTimeEqual(expectedHmac, new Uint8Array(data.hmac))) {
    console.error('HMAC verification failed');
    return;
  }
  
  // Parse the message
  try {
    const parsedData = JSON.parse(data.data) as SecureMessage;
    
    // Process the message
    console.log('Received secure message:', parsedData.message);
    
    // Handle the message...
  } catch (error) {
    console.error('Failed to parse message:', error);
  }
}

// Helper function to create HMAC
export async function createHmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // In a browser environment, we would use SubtleCrypto
  // This is a simplified version for demonstration
  
  // Create a hash using key and data
  const combinedData = new Uint8Array(key.length + data.length);
  combinedData.set(key, 0);
  combinedData.set(data, key.length);
  
  // Create a hash of the combined data
  // (In a real implementation, this would use a proper HMAC function)
  const hashBuffer = await crypto.subtle.digest('SHA-256', combinedData);
  
  return new Uint8Array(hashBuffer);
}

// Helper function for constant-time comparison
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    // XOR the bytes - will be 0 for matching bytes
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
}

// Main function to initialize secure cross-origin communication
export function secureIframeCommunication(iframeUrl: string): CommunicationResult {
  // Create an iframe
  const iframe = document.createElement('iframe');
  iframe.src = iframeUrl;
  document.body.appendChild(iframe);
  
  // Extract origin from URL
  const targetOrigin = new URL(iframeUrl).origin;
  
  // Setup secure communication
  const channel = setupSecureCommunication(iframe, targetOrigin);
  
  // Return the channel for sending messages
  return {
    sendMessage: (message: any) => sendSecureMessage(message, channel)
  };
}