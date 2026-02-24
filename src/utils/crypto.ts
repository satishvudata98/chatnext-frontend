/**
 * End-to-End Encryption Utilities
 * Uses Web Crypto API for secure client-side encryption
 */

// Types for our crypto operations
export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface EncryptedMessage {
  ciphertext: string; // base64 encoded
  iv: string; // base64 encoded
  keyId: string; // identifier for the encryption key used
}

export interface ConversationKey {
  key: CryptoKey | string; // Can be CryptoKey or base64 string for storage
  keyId: string;
  createdAt: number;
}

// Storage keys for localStorage
const USER_KEYPAIR_KEY = 'e2ee_user_keypair';
const CONVERSATION_KEYS_KEY = 'e2ee_conversation_keys';

/**
 * Generate ECDH key pair for the user
 */
export async function generateUserKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true, // extractable
    ['deriveKey', 'deriveBits']
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Export public key to share with other users
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

/**
 * Import public key from other user
 */
export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  const publicKeyData = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'spki',
    publicKeyData,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    []
  );
}

/**
 * Derive shared secret from user's private key and other's public key
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  otherPublicKey: CryptoKey
): Promise<CryptoKey> {
  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: otherPublicKey,
    },
    privateKey,
    256
  );

  // Derive AES key from shared secret using HKDF
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // random salt would be better, but for simplicity
      info: new Uint8Array([0x65, 0x32, 0x65, 0x65]), // "e2ee" in bytes
    },
    await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveKey']
    ),
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a message using AES-GCM
 */
export async function encryptMessage(
  message: string,
  key: CryptoKey,
  keyId: string
): Promise<EncryptedMessage> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    data
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
    keyId,
  };
}

/**
 * Decrypt a message using AES-GCM
 */
export async function decryptMessage(
  encryptedMessage: EncryptedMessage,
  key: CryptoKey
): Promise<string> {
  const ciphertext = Uint8Array.from(atob(encryptedMessage.ciphertext), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(encryptedMessage.iv), c => c.charCodeAt(0));

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Generate a unique key ID
 */
export function generateKeyId(): string {
  return crypto.randomUUID();
}

/**
 * Store user's key pair in localStorage
 */
export async function storeUserKeyPair(keyPair: KeyPair): Promise<void> {
  const exportedPrivate = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const exportedPublic = await crypto.subtle.exportKey('spki', keyPair.publicKey);

  const keyData = {
    privateKey: btoa(String.fromCharCode(...new Uint8Array(exportedPrivate))),
    publicKey: btoa(String.fromCharCode(...new Uint8Array(exportedPublic))),
  };

  localStorage.setItem(USER_KEYPAIR_KEY, JSON.stringify(keyData));
}

/**
 * Load user's key pair from localStorage
 */
export async function loadUserKeyPair(): Promise<KeyPair | null> {
  const stored = localStorage.getItem(USER_KEYPAIR_KEY);
  if (!stored) return null;

  try {
    const keyData = JSON.parse(stored);

    const privateKeyData = Uint8Array.from(atob(keyData.privateKey), c => c.charCodeAt(0));
    const publicKeyData = Uint8Array.from(atob(keyData.publicKey), c => c.charCodeAt(0));

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );

    const publicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      []
    );

    return { privateKey, publicKey };
  } catch (error) {
    console.error('Failed to load user key pair:', error);
    return null;
  }
}

/**
 * Store conversation encryption key
 */
export function storeConversationKey(conversationId: string, conversationKey: ConversationKey): void {
  const stored = localStorage.getItem(CONVERSATION_KEYS_KEY);
  const keys = stored ? JSON.parse(stored) : {};
  keys[conversationId] = conversationKey;
  localStorage.setItem(CONVERSATION_KEYS_KEY, JSON.stringify(keys));
}

/**
 * Load conversation encryption key
 */
export async function loadConversationKey(conversationId: string): Promise<ConversationKey | null> {
  const stored = localStorage.getItem(CONVERSATION_KEYS_KEY);
  if (!stored) return null;

  const keys = JSON.parse(stored);
  const keyData = keys[conversationId];
  if (!keyData) return null;

  try {
    // Re-import the key from raw data (we'd need to store the raw key data)
    // For now, return the stored data - we'll need to modify this
    return keyData;
  } catch (error) {
    console.error('Failed to load conversation key:', error);
    return null;
  }
}

/**
 * Initialize E2EE for a user (generate key pair if not exists)
 */
export async function initializeE2EE(): Promise<KeyPair> {
  let keyPair = await loadUserKeyPair();
  if (!keyPair) {
    keyPair = await generateUserKeyPair();
    await storeUserKeyPair(keyPair);
  }
  return keyPair;
}

/**
 * Get user's public key for sharing
 */
export async function getUserPublicKey(): Promise<string | null> {
  const keyPair = await loadUserKeyPair();
  if (!keyPair) return null;
  return exportPublicKey(keyPair.publicKey);
}

/**
 * Establish encryption key for a conversation
 */
export async function establishConversationKey(
  conversationId: string,
  otherPublicKeyBase64: string
): Promise<CryptoKey> {
  const userKeyPair = await loadUserKeyPair();
  if (!userKeyPair) throw new Error('User key pair not found');

  const otherPublicKey = await importPublicKey(otherPublicKeyBase64);
  const sharedKey = await deriveSharedSecret(userKeyPair.privateKey, otherPublicKey);

  // Store the key for future use
  const exportedKey = await crypto.subtle.exportKey('raw', sharedKey);
  const storedKey: ConversationKey = {
    key: btoa(String.fromCharCode(...new Uint8Array(exportedKey))), // Store as base64 string
    keyId: generateKeyId(),
    createdAt: Date.now(),
  };
  storeConversationKey(conversationId, storedKey);

  return sharedKey;
}

/**
 * Load and import conversation key for decryption
 */
export async function loadConversationKeyForDecryption(conversationId: string): Promise<CryptoKey | null> {
  const stored = localStorage.getItem(CONVERSATION_KEYS_KEY);
  if (!stored) return null;

  const keys = JSON.parse(stored);
  const keyData = keys[conversationId];
  if (!keyData) return null;

  try {
    const keyDataRaw = Uint8Array.from(atob(keyData.key), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
      'raw',
      keyDataRaw,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    console.error('Failed to import conversation key:', error);
    return null;
  }
}

/**
 * Derive encryption key from password for securing private key
 */
async function derivePasswordKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordData,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      iterations: 100000,
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt private key with password for server storage
 */
export async function encryptPrivateKeyWithPassword(
  privateKey: CryptoKey,
  password: string
): Promise<{ encryptedKey: string; salt: string; iv: string }> {
  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Derive encryption key from password
  const passwordKey = await derivePasswordKey(password, salt);

  // Export private key
  const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', privateKey);

  // Encrypt private key
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    passwordKey,
    exportedPrivateKey
  );

  return {
    encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * Decrypt private key with password from server storage
 */
export async function decryptPrivateKeyWithPassword(
  encryptedKeyBase64: string,
  saltBase64: string,
  ivBase64: string,
  password: string
): Promise<CryptoKey> {
  const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
  const encryptedData = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));

  // Derive encryption key from password
  const passwordKey = await derivePasswordKey(password, salt);

  // Decrypt private key
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    passwordKey,
    encryptedData
  );

  // Import decrypted private key
  return crypto.subtle.importKey(
    'pkcs8',
    decryptedData,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
}
