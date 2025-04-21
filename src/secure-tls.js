/**
 * Secure implementation of HTTP communication with TLS
 * 
 * Key security features:
 * - Proper certificate validation
 * - Strong cipher suites
 * - Secure protocols
 */

const https = require('https');
const tls = require('tls');
const crypto = require('crypto');

// Function 1: Create secure HTTPS options
function createSecureHttpsOptions() {
  return {
    // Minimum TLS version
    minVersion: 'TLSv1.2',
    
    // Prefer modern ciphers
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384',
    
    // Secure options
    honorCipherOrder: true,
    
    // Enable OCSP stapling
    requestOCSP: true,
    
    // Reject unauthorized certificates
    rejectUnauthorized: true
  };
}

// Function 2: Make secure HTTPS request
function makeSecureHttpsRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    // Parse the URL
    const parsedUrl = new URL(url);
    
    // Merge options with secure defaults
    const requestOptions = {
      ...createSecureHttpsOptions(),
      ...options,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 443,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET'
    };
    
    // Create the request
    const req = https.request(requestOptions, (res) => {
      // Check for secure redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // Ensure redirects only go to HTTPS URLs
        const redirectUrl = new URL(res.headers.location, url);
        if (redirectUrl.protocol !== 'https:') {
          reject(new Error('Insecure redirect detected'));
          return;
        }
      }
      
      // Collect the response data
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data
        });
      });
    });
    
    // Handle errors
    req.on('error', (error) => {
      reject(error);
    });
    
    // Send request body if provided
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

// Function 3: Validate certificate
function validateCertificate(cert, hostname) {
  // Check certificate validity period
  const now = Date.now();
  const certNotBefore = new Date(cert.valid_from).getTime();
  const certNotAfter = new Date(cert.valid_to).getTime();
  
  if (now < certNotBefore || now > certNotAfter) {
    return {
      valid: false,
      reason: 'Certificate is not valid at the current time'
    };
  }
  
  // Check hostname
  const altNames = cert.subjectaltname;
  if (altNames) {
    const names = altNames.split(', ').map(name => {
      const [type, value] = name.split(':');
      return { type, value };
    });
    
    // Check if hostname matches any of the alt names
    const hostnameMatch = names.some(name => {
      if (name.type === 'DNS') {
        // Check for wildcard certificates
        if (name.value.startsWith('*.')) {
          const wildcardDomain = name.value.slice(2);
          const hostnameParts = hostname.split('.');
          hostnameParts.shift();
          const hostnameDomain = hostnameParts.join('.');
          return hostnameDomain === wildcardDomain;
        }
        
        return name.value === hostname;
      }
      return false;
    });
    
    if (!hostnameMatch) {
      return {
        valid: false,
        reason: 'Certificate does not match hostname'
      };
    }
  }
  
  return {
    valid: true
  };
}

// Function 4: Pin certificates
function configureCertificatePinning(hostname, publicKeyHash) {
  // Return a checking function for the specified hostname and public key hash
  return (cert) => {
    // Get the public key from the certificate
    const publicKey = cert.pubkey;
    
    // Hash the public key
    const hash = crypto.createHash('sha256').update(publicKey).digest('base64');
    
    // Compare with the pinned hash
    return hash === publicKeyHash;
  };
}

// Main function for secure TLS communication
async function secureTlsCommunication(url, pinningConfig = null) {
  try {
    // Create options with secure defaults
    const options = createSecureHttpsOptions();
    
    // Add certificate pinning if provided
    if (pinningConfig) {
      options.checkServerIdentity = (hostname, cert) => {
        // First validate the certificate
        const validation = validateCertificate(cert, hostname);
        if (!validation.valid) {
          return new Error(validation.reason);
        }
        
        // Then check certificate pinning
        const pinChecker = configureCertificatePinning(hostname, pinningConfig.publicKeyHash);
        if (!pinChecker(cert)) {
          return new Error('Certificate public key does not match pinned hash');
        }
        
        return undefined; // Certificate is valid
      };
    }
    
    // Make the secure request
    const response = await makeSecureHttpsRequest(url, options);
    
    return response;
  } catch (error) {
    console.error(`Secure TLS communication error: ${error.message}`);
    throw error;
  }
}

module.exports = {
  createSecureHttpsOptions,
  makeSecureHttpsRequest,
  validateCertificate,
  configureCertificatePinning,
  secureTlsCommunication
};