/**
 * Type definitions for browser-specific APIs
 * These are used in examples that include browser functionality
 */

// Chrome Storage API
export interface ChromeStorage {
  local: {
    set: (items: object, callback?: () => void) => Promise<void>;
    get: (keys: string | string[] | object | null) => Promise<any>;
  };
}

// Extended Window interface for browser examples
export interface ExtendedWindow extends Window {
  crypto: Crypto;
  parent: Window;
  chrome?: {
    storage: ChromeStorage;
    runtime: {
      sendMessage: (message: any, callback?: (response: any) => void) => void;
      onMessage: {
        addListener: (
          listener: (
            message: any,
            sender: { id: string; url?: string },
            sendResponse: (response?: any) => void
          ) => boolean | void
        ) => void;
      };
    };
  };
}

// Message data for cross-origin communication
export interface SecureMessage {
  message: any;
  nonce: number[];
}

export interface InsecureMessage {
  data: string;
}

// Secure message with HMAC for transmission
export interface SecureMessageEnvelope {
  data: string;
  hmac: number[];
}

// Insecure message for transmission
export interface InsecureMessageEnvelope {
  data: string;
}

// Channel for secure communication
export interface CommunicationChannel {
  key: Uint8Array;
  targetOrigin: string;
  iframe: HTMLIFrameElement;
}

// Types for browser extension
export interface KeyData {
  encrypted: number[];
  iv: number[];
  timestamp?: number;
}

// Keystore data in storage
export interface StoredKeystore {
  [keyName: string]: {
    encrypted: number[];
    iv: number[];
    timestamp: number;
  };
}