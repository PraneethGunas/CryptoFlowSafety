export interface Transaction {
  inputs: TransactionInput[];
  outputs: TransactionOutput[];
  [key: string]: any;
}

export interface TransactionInput {
  txid: string;
  vout: number;
  [key: string]: any;
}

export interface TransactionOutput {
  address: string;
  value: number;
  [key: string]: any;
}

export interface SignedTransaction {
  transaction: Transaction;
  signature: string;
  txid: string;
}

export interface KeyStore {
  version: number;
  id?: string;
  address?: string;
  crypto: {
    ciphertext: string;
    cipherparams: {
      iv: string;
    };
    cipher: string;
    kdf: string;
    kdfparams: {
      dklen: number;
      salt: string;
      n?: number;
      r?: number;
      p?: number;
    };
    mac?: string;
  };
  [key: string]: any;
}

export interface InsecureKeyStore {
  version: number;
  ciphertext: string;
  iv: string;
  salt: string;
  [key: string]: any;
}

export interface Signature {
  r: string;
  s: string;
}

export interface WalletResult {
  mnemonic: string;
  seed: string;
}

export interface EthereumKeyResult {
  keystore: KeyStore | InsecureKeyStore;
  result: string;
  keystoreId?: string;
}

export interface CommunicationChannel {
  key: Uint8Array;
  targetOrigin: string;
  iframe: HTMLIFrameElement;
}

export interface SecureRandomResult {
  randomNumber: number;
  randomString: string;
  key: string;
}

export interface InsecureRandomResult {
  randomNumber: number;
  randomString: string;
  encrypted: {
    encrypted: string;
    key: string;
    iv: string;
  };
}

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  data: string;
  error?: string;
}

export type BufferLike = Buffer | Uint8Array | string;
