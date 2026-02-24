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
    console.log("[RESTORE_SERVER] Starting restore from server...");
    console.log("[RESTORE_SERVER] Input validation:", {
      hasEncryptedKey: !!encryptedKeyBase64,
      hasSalt: !!saltBase64,
      hasIv: !!ivBase64,
      hasPublicKey: !!publicKeyBase64,
      hasPassword: !!password,
      passwordLength: password?.length || 0,
    });

    // Decrypt the private key
    console.log("[RESTORE_SERVER] Decrypting private key from server...");
    const privateKey = await decryptPrivateKeyWithPassword(
      encryptedKeyBase64,
      saltBase64,
      ivBase64,
      password
    );
    console.log("[RESTORE_SERVER] ✓ Private key decrypted");

    // Create full KeyPair with both keys
    console.log("[RESTORE_SERVER] Restoring full keypair...");
    const keyPair = await restoreKeyPairFromDecrypted(privateKey, publicKeyBase64);
    console.log("[RESTORE_SERVER] ✓ Keypair restoration complete");
    
    return keyPair;
  } catch (error) {
    console.error("[RESTORE_SERVER] ✗ Restoration failed:", error);
    console.error("[RESTORE_SERVER] Error type:", (error as Error).name);
    console.error("[RESTORE_SERVER] Error message:", (error as Error).message);
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
    console.log("[IMPORT_PUBLIC_KEY] Importing public key from base64...");
    console.log("[IMPORT_PUBLIC_KEY] Input:", {
      hasKeyData: !!publicKeyBase64,
      dataLength: publicKeyBase64?.length || 0,
    });

    const publicKeyData = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));
    console.log("[IMPORT_PUBLIC_KEY] Decoded size:", publicKeyData.length);

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
    console.log("[IMPORT_PUBLIC_KEY] ✓ Public key imported successfully");
    return publicKey;
  } catch (error) {
    console.error("[IMPORT_PUBLIC_KEY] ✗ Import failed:", error);
    console.error("[IMPORT_PUBLIC_KEY] Error type:", (error as Error).name);
    console.error("[IMPORT_PUBLIC_KEY] Error message:", (error as Error).message);
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
    console.log("[DECRYPT_MSG] Starting message decryption...");
    console.log("[DECRYPT_MSG] Input validation:", {
      hasCiphertext: !!encryptedMessage.ciphertext,
      ciphertextLength: encryptedMessage.ciphertext?.length || 0,
      hasIv: !!encryptedMessage.iv,
      ivLength: encryptedMessage.iv?.length || 0,
      hasKey: !!key,
      keyId: encryptedMessage.keyId,
    });

    const ciphertext = Uint8Array.from(atob(encryptedMessage.ciphertext), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(encryptedMessage.iv), c => c.charCodeAt(0));

    console.log("[DECRYPT_MSG] Decoded sizes:", {
      ciphertextSize: ciphertext.length,
      ivSize: iv.length,
    });

    console.log("[DECRYPT_MSG] Attempting AES-GCM decryption...");
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      ciphertext
    );

    console.log("[DECRYPT_MSG] ✓ Decryption successful, decrypted size:", decrypted.byteLength);

    const decoder = new TextDecoder();
    const result = decoder.decode(decrypted);
    console.log("[DECRYPT_MSG] ✓ Message decoded, length:", result.length);
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
    console.log("[ESTABLISH_CONV_KEY] Establishing conversation key for:", conversationId);

    const userKeyPair = await loadUserKeyPair();
    if (!userKeyPair) throw new Error('User key pair not found');

    const otherPublicKey = await importPublicKey(otherPublicKeyBase64);
    const sharedKey = await deriveSharedSecret(userKeyPair.privateKey, otherPublicKey);
    console.log("[ESTABLISH_CONV_KEY] ✓ Shared key derived");

    // Store the key locally for immediate use
    const exportedKey = await crypto.subtle.exportKey('raw', sharedKey);
    const storedKey: ConversationKey = {
      key: btoa(String.fromCharCode(...new Uint8Array(exportedKey))),
      keyId: generateKeyId(),
      createdAt: Date.now(),
    };
    storeConversationKey(conversationId, storedKey);
    console.log("[ESTABLISH_CONV_KEY] ✓ Key stored locally");

    // Also store encrypted version on server for cross-device support
    try {
      const tempPassword = sessionStorage.getItem("tempPassword");
      if (tempPassword) {
        console.log("[ESTABLISH_CONV_KEY] Storing key on server...");
        const encryptedKeyData = await encryptConversationKeyWithPassword(exportedKey, tempPassword);
        const { storeConversationKeyOnServer } = await import("../api/api");
        await storeConversationKeyOnServer(conversationId, encryptedKeyData);
        console.log("[ESTABLISH_CONV_KEY] ✓ Key stored on server");
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
    console.log("[LOAD_CONV_KEY] Loading conversation key for:", conversationId);

    const stored = localStorage.getItem(CONVERSATION_KEYS_KEY);
    console.log("[LOAD_CONV_KEY] Stored keys found:", !!stored);

    if (!stored) {
      console.log("[LOAD_CONV_KEY] ✗ No conversation keys in localStorage, trying server...");

      // Try to load from server
      try {
        const tempPassword = sessionStorage.getItem("tempPassword");
        if (!tempPassword) {
          console.log("[LOAD_CONV_KEY] No temp password available for server decryption");
          return null;
        }

        console.log("[LOAD_CONV_KEY] Fetching keys from server...");
        const { fetchConversationKeysFromServer } = await import("../api/api");
        const response = await fetchConversationKeysFromServer() as {
          success: boolean;
          conversationKeys: Record<string, { encryptedKey: string; salt: string; iv: string; storedAt: string }>;
        };

        if (response.success && response.conversationKeys && response.conversationKeys[conversationId]) {
          console.log("[LOAD_CONV_KEY] Found key on server, decrypting...");
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
          console.log("[LOAD_CONV_KEY] ✓ Key restored from server and cached locally");

          return decryptedKey;
        } else {
          console.log("[LOAD_CONV_KEY] No key found on server");
          return null;
        }
      } catch (serverError) {
        console.error("[LOAD_CONV_KEY] Failed to load from server:", serverError);
        return null;
      }
    }

    const keys = JSON.parse(stored);
    console.log("[LOAD_CONV_KEY] Available conversation IDs:", Object.keys(keys));

    const keyData = keys[conversationId];
    console.log("[LOAD_CONV_KEY] Key data found for this conversation:", !!keyData);

    if (!keyData) {
      console.log("[LOAD_CONV_KEY] ✗ No key data for conversation", conversationId);
      return null;
    }

    console.log("[LOAD_CONV_KEY] Key data structure:", {
      hasKey: !!keyData.key,
      keyLength: keyData.key?.length || 0,
      hasCreatedAt: !!keyData.createdAt,
    });

    const keyDataRaw = Uint8Array.from(atob(keyData.key), c => c.charCodeAt(0));
    console.log("[LOAD_CONV_KEY] Decoded key size:", keyDataRaw.length);

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

    console.log("[LOAD_CONV_KEY] ✓ Conversation key imported successfully");
    return importedKey;
  } catch (error) {
    console.error("[LOAD_CONV_KEY] ✗ Failed to load/import conversation key:", error);
    console.error("[LOAD_CONV_KEY] Error type:", (error as Error).name);
    console.error("[LOAD_CONV_KEY] Error message:", (error as Error).message);
    return null;
  }
}

/**
 * Derive encryption key from password for securing private key
 */
async function derivePasswordKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  try {
    console.log("[DERIVE_PWD_KEY] Deriving password key with PBKDF2...");
    console.log("[DERIVE_PWD_KEY] Input:", {
      passwordLength: password?.length || 0,
      saltSize: salt.length,
      iterations: 100000,
      hash: "SHA-256",
    });

    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    console.log("[DERIVE_PWD_KEY] Encoded password size:", passwordData.length);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveKey']
    );
    console.log("[DERIVE_PWD_KEY] ✓ Base key imported");

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
    console.log("[DERIVE_PWD_KEY] ✓ Key derived successfully");
    return derivedKey;
  } catch (error) {
    console.error("[DERIVE_PWD_KEY] ✗ Key derivation failed:", error);
    console.error("[DERIVE_PWD_KEY] Error type:", (error as Error).name);
    console.error("[DERIVE_PWD_KEY] Error message:", (error as Error).message);
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
    console.log("[DECRYPT_KEY] Starting private key decryption...");
    console.log("[DECRYPT_KEY] Input validation:", {
      hasEncryptedKey: !!encryptedKeyBase64,
      hasSalt: !!saltBase64,
      hasIv: !!ivBase64,
      hasPassword: !!password,
    });

    const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const encryptedData = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));

    console.log("[DECRYPT_KEY] Decoded sizes:", {
      saltSize: salt.length,
      ivSize: iv.length,
      encryptedDataSize: encryptedData.length,
    });

    // Derive encryption key from password
    console.log("[DECRYPT_KEY] Deriving password key...");
    const passwordKey = await derivePasswordKey(password, salt);
    console.log("[DECRYPT_KEY] ✓ Password key derived");

    // Decrypt private key
    console.log("[DECRYPT_KEY] Attempting AES-GCM decryption...");
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      passwordKey,
      encryptedData
    );
    console.log("[DECRYPT_KEY] ✓ Decryption successful, decrypted size:", decryptedData.byteLength);

    // Import decrypted private key
    console.log("[DECRYPT_KEY] Importing ECDH private key...");
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
    console.log("[DECRYPT_KEY] ✓ Private key imported successfully");
    
    return privateKey;
  } catch (error) {
    console.error("[DECRYPT_KEY] ✗ Decryption failed:", error);
    console.error("[DECRYPT_KEY] Error type:", (error as Error).name);
    console.error("[DECRYPT_KEY] Error message:", (error as Error).message);
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
    console.log("[ENCRYPT_CONV_KEY] Encrypting conversation key with password...");

    // Generate random salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    console.log("[ENCRYPT_CONV_KEY] Generated salt and IV");

    // Derive encryption key from password
    const passwordKey = await derivePasswordKey(password, salt);
    console.log("[ENCRYPT_CONV_KEY] ✓ Password key derived");

    // Encrypt the conversation key
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      passwordKey,
      conversationKeyRaw
    );

    console.log("[ENCRYPT_CONV_KEY] ✓ Encryption successful");

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
    console.log("[DECRYPT_CONV_KEY] Decrypting conversation key...");

    const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const encryptedData = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));

    console.log("[DECRYPT_CONV_KEY] Decoded sizes:", {
      saltSize: salt.length,
      ivSize: iv.length,
      encryptedDataSize: encryptedData.length,
    });

    // Derive decryption key from password
    console.log("[DECRYPT_CONV_KEY] Deriving password key...");
    const passwordKey = await derivePasswordKey(password, salt);

    // Decrypt conversation key
    console.log("[DECRYPT_CONV_KEY] Attempting AES-GCM decryption...");
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      passwordKey,
      encryptedData
    );

    console.log("[DECRYPT_CONV_KEY] ✓ Decryption successful");

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

    console.log("[DECRYPT_CONV_KEY] ✓ Key imported successfully");
    return conversationKey;
  } catch (error) {
    console.error("[DECRYPT_CONV_KEY] ✗ Decryption failed:", error);
    console.error("[DECRYPT_CONV_KEY] Error type:", (error as Error).name);
    console.error("[DECRYPT_CONV_KEY] Error message:", (error as Error).message);
    throw error;
  }
}
