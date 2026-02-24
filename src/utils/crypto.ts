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
 * Restore full KeyPair from decrypted private key and public key
 */
export async function restoreKeyPairFromDecrypted(
  privateKeyCryptoKey: CryptoKey,
  publicKeyBase64: string
): Promise<KeyPair> {
  // Import the public key from base64
  const publicKey = await importPublicKey(publicKeyBase64);
  
  return {
    privateKey: privateKeyCryptoKey,
    publicKey: publicKey,
  };
}

/**
 * Decrypt private key from server and restore complete KeyPair
 */
export async function restoreKeyPairFromServer(
  encryptedKeyBase64: string,
  saltBase64: string,
  ivBase64: string,
  publicKeyBase64: string,
  password: string
): Promise<KeyPair> {
  try {
    // Decrypt the private key
    const privateKey = await decryptPrivateKeyWithPassword(
      encryptedKeyBase64,
      saltBase64,
      ivBase64,
      password
    );

    // Create full KeyPair with both keys
    const keyPair = await restoreKeyPairFromDecrypted(privateKey, publicKeyBase64);
    
    return keyPair;
  } catch (error) {
    console.error("[RESTORE_SERVER] ✗ Restoration failed:", error);
    throw error;
  }
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
  try {
  
    const publicKeyData = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));

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
    return publicKey;
  } catch (error) {
    console.error("[IMPORT_PUBLIC_KEY] ✗ Import failed:", error);
    throw error;
  }
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
  try {

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
    const result = decoder.decode(decrypted);
    return result;
  } catch (error) {
    console.error("[DECRYPT_MSG] ✗ Decryption failed:", error);
    console.error("[DECRYPT_MSG] Error type:", (error as Error).name);
    console.error("[DECRYPT_MSG] Error message:", (error as Error).message);
    throw error;
  }
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
  try {

    const userKeyPair = await loadUserKeyPair();
    if (!userKeyPair) throw new Error('User key pair not found');

    const otherPublicKey = await importPublicKey(otherPublicKeyBase64);
    const sharedKey = await deriveSharedSecret(userKeyPair.privateKey, otherPublicKey);

    // Store the key locally for immediate use
    const exportedKey = await crypto.subtle.exportKey('raw', sharedKey);
    const storedKey: ConversationKey = {
      key: btoa(String.fromCharCode(...new Uint8Array(exportedKey))),
      keyId: generateKeyId(),
      createdAt: Date.now(),
    };
    storeConversationKey(conversationId, storedKey);

    // Also store encrypted version on server for cross-device support
    try {
      const tempPassword = sessionStorage.getItem("tempPassword");
      if (tempPassword) {
        const encryptedKeyData = await encryptConversationKeyWithPassword(exportedKey, tempPassword);
        const { storeConversationKeyOnServer } = await import("../api/api");
        await storeConversationKeyOnServer(conversationId, encryptedKeyData);
      } else {
        console.log("[ESTABLISH_CONV_KEY] No temp password available, skipping server storage");
      }
    } catch (serverError) {
      console.error("[ESTABLISH_CONV_KEY] Failed to store on server:", serverError);
      // Don't fail the whole operation if server storage fails
    }

    return sharedKey;
  } catch (error) {
    console.error("[ESTABLISH_CONV_KEY] ✗ Failed to establish conversation key:", error);
    throw error;
  }
}

/**
 * Load and import conversation key for decryption
 */
export async function loadConversationKeyForDecryption(conversationId: string): Promise<CryptoKey | null> {
  try {

    const stored = localStorage.getItem(CONVERSATION_KEYS_KEY);

    if (!stored) {

      // Try to load from server
      try {
        const tempPassword = sessionStorage.getItem("tempPassword");
        if (!tempPassword) {
          return null;
        }

        const { fetchConversationKeysFromServer } = await import("../api/api");
        const response = await fetchConversationKeysFromServer() as {
          success: boolean;
          conversationKeys: Record<string, { encryptedKey: string; salt: string; iv: string; storedAt: string }>;
        };

        if (response.success && response.conversationKeys && response.conversationKeys[conversationId]) {
          const keyData = response.conversationKeys[conversationId];
          const decryptedKey = await decryptConversationKeyWithPassword(
            keyData.encryptedKey,
            keyData.salt,
            keyData.iv,
            tempPassword
          );

          // Store back in localStorage for future use
          const exportedKey = await crypto.subtle.exportKey('raw', decryptedKey);
          const storedKey: ConversationKey = {
            key: btoa(String.fromCharCode(...new Uint8Array(exportedKey))),
            keyId: generateKeyId(),
            createdAt: Date.now(),
          };
          storeConversationKey(conversationId, storedKey);

          return decryptedKey;
        } else {
          return null;
        }
      } catch (serverError) {
        console.error("[LOAD_CONV_KEY] Failed to load from server:", serverError);
        return null;
      }
    }

    const keys = JSON.parse(stored);

    const keyData = keys[conversationId];

    if (!keyData) {
      return null;
    }

    const keyDataRaw = Uint8Array.from(atob(keyData.key), c => c.charCodeAt(0));

    const importedKey = await crypto.subtle.importKey(
      'raw',
      keyDataRaw,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );

    return importedKey;
  } catch (error) {
    console.error("[LOAD_CONV_KEY] ✗ Failed to load/import conversation key:", error);
    return null;
  }
}

/**
 * Derive encryption key from password for securing private key
 */
async function derivePasswordKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  try {

    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
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
    return derivedKey;
  } catch (error) {
    console.error("[DERIVE_PWD_KEY] ✗ Key derivation failed:", error);
    throw error;
  }
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
  try {

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
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      decryptedData,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    
    return privateKey;
  } catch (error) {
    console.error("[DECRYPT_KEY] ✗ Decryption failed:", error);
    throw error;
  }
}

/**
 * Encrypt a conversation key with password for server storage
 */
export async function encryptConversationKeyWithPassword(
  conversationKeyRaw: ArrayBuffer,
  password: string
): Promise<{ encryptedKey: string; salt: string; iv: string }> {
  try {

    // Generate random salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));


    // Derive encryption key from password
    const passwordKey = await derivePasswordKey(password, salt);

    // Encrypt the conversation key
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      passwordKey,
      conversationKeyRaw
    );


    return {
      encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
      salt: btoa(String.fromCharCode(...salt)),
      iv: btoa(String.fromCharCode(...iv)),
    };
  } catch (error) {
    console.error("[ENCRYPT_CONV_KEY] ✗ Encryption failed:", error);
    throw error;
  }
}

/**
 * Decrypt a conversation key that was encrypted with password
 */
export async function decryptConversationKeyWithPassword(
  encryptedKeyBase64: string,
  saltBase64: string,
  ivBase64: string,
  password: string
): Promise<CryptoKey> {
  try {

    const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const encryptedData = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));

    // Derive decryption key from password
    const passwordKey = await derivePasswordKey(password, salt);

    // Decrypt conversation key
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      passwordKey,
      encryptedData
    );


    // Import as AES-GCM key
    const conversationKey = await crypto.subtle.importKey(
      'raw',
      decryptedData,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );

    return conversationKey;
  } catch (error) {
    console.error("[DECRYPT_CONV_KEY] ✗ Decryption failed:", error);
    throw error;
  }
}
