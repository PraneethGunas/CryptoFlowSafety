/**
 * Insecure implementation of HTTP communication with TLS
 * 
 * Security issues:
 * - Disabled certificate validation
 * - Weak cipher suites
 * - Outdated protocols
 * - Interprocedural weakness where security settings propagate
 */

import * as https from 'https';
import * as tls from 'tls';
import { URL } from 'url';
import { HttpResponse } from './types/common';

interface HttpsOptions {
  minVersion?: string;
  ciphers?: string;
  rejectUnauthorized?: boolean;
  hostname?: string;
  servername?: string;
  port?: number;
  path?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  checkServerIdentity?: (hostname: string, cert: tls.PeerCertificate) => Error | undefined;
}

// Function 1: Create insecure HTTPS options (INSECURE)
export function createInsecureHttpsOptions(): HttpsOptions {
  return {
    // VULNERABILITY: Allowing old TLS versions
    minVersion: 'TLSv1',
    
    // VULNERABILITY: Allowing weak ciphers
    ciphers: 'HIGH:MEDIUM:LOW:!aNULL:!eNULL',
    
    // VULNERABILITY: Disabling certificate validation
    rejectUnauthorized: false
  };
}

// Global variable to store insecure options (INSECURE)
const globalInsecureOptions: HttpsOptions = createInsecureHttpsOptions();

// Function 2: Make insecure HTTPS request (INSECURE)
export function makeInsecureHttpsRequest(url: string, options: HttpsOptions = {}): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    // Parse the URL
    const parsedUrl = new URL(url);
    
    // VULNERABILITY: Merging with global insecure options
    // This affects all requests using this function
    const requestOptions: HttpsOptions = {
      ...globalInsecureOptions,
      ...options,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port ? parseInt(parsedUrl.port) : 443,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET'
    };
    
    // Create the request
    const req = https.request(requestOptions, (res) => {
      // VULNERABILITY: Not validating secure redirects
      
      // Collect the response data
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers as Record<string, string>,
          data
        });
      });
    });
    
    // Handle errors
    req.on('error', (error) => {
      // VULNERABILITY: Silently continuing on some errors
      if (error.code === 'CERT_HAS_EXPIRED' || error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
        console.error(`Certificate error (ignored): ${error.message}`);
        resolve({
          statusCode: 0,
          headers: {},
          data: '',
          error: error.message
        });
      } else {
        reject(error);
      }
    });
    
    // Send request body if provided
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

// Function 3: Custom certificate validator that accepts all (INSECURE)
export function acceptAllCertificates(): (hostname: string, cert: tls.PeerCertificate) => Error | undefined {
  // VULNERABILITY: Accepting all certificates without validation
  return (hostname: string, cert: tls.PeerCertificate) => {
    // Always return undefined (no error) to accept any certificate
    return undefined;
  };
}

// Function 4: Make request with custom domain (INSECURE)
export async function makeRequestWithCustomDomain(url: string, targetDomain: string): Promise<HttpResponse> {
  // Parse the URL
  const parsedUrl = new URL(url);
  
  // VULNERABILITY: Overriding the domain to connect to
  // This can be used to bypass certificate validation
  const options: HttpsOptions = {
    ...createInsecureHttpsOptions(),
    hostname: targetDomain,
    servername: parsedUrl.hostname, // SNI will still use the original hostname
    headers: {
      'Host': parsedUrl.hostname // HTTP Host header will be the original
    },
    path: parsedUrl.pathname + parsedUrl.search,
    method: 'GET'
  };
  
  // VULNERABILITY: Bypassing certificate validation
  options.checkServerIdentity = acceptAllCertificates();
  
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers as Record<string, string>,
          data
        });
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.end();
  });
}

// Main function for insecure TLS communication
export async function insecureTlsCommunication(url: string, bypassDomain: string | null = null): Promise<HttpResponse> {
  try {
    // VULNERABILITY: Conditionally using certificate bypassing
    if (bypassDomain) {
      // Use domain bypassing
      return await makeRequestWithCustomDomain(url, bypassDomain);
    } else {
      // Use standard insecure request
      return await makeInsecureHttpsRequest(url);
    }
  } catch (error) {
    console.error(`TLS communication error: ${(error as Error).message}`);
    // VULNERABILITY: Retrying with certificate validation disabled
    console.log('Retrying with certificate validation disabled...');
    return await makeInsecureHttpsRequest(url, { rejectUnauthorized: false });
  }
}