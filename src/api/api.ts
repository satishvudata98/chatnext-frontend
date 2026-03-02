import { config } from "../config/config";
import { auth } from "../lib/firebase";

async function getAuthHeaders(): Promise<Record<string, string>> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (auth.currentUser) {
    const token = await auth.currentUser.getIdToken();
    headers.Authorization = `Bearer ${token}`;
    localStorage.setItem("firebaseToken", token);
    return headers;
  }

  const cachedToken = localStorage.getItem("firebaseToken");
  if (cachedToken) {
    headers.Authorization = `Bearer ${cachedToken}`;
  }

  return headers;
}

async function apiRequest<T>(
  endpoint: string,
  method: "GET" | "POST" = "GET",
  body?: unknown,
): Promise<T> {
  const url = `${config.apiUrl}${endpoint}`;

  const options: RequestInit = {
    method,
    headers: await getAuthHeaders(),
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(url, options);

  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem("firebaseToken");
      localStorage.removeItem("user");
      globalThis.location.href = "/login";
    }

    const errorData = await res.json().catch(() => null);
    throw new Error(errorData?.message || `HTTP error: ${res.status}`);
  }

  return res.json();
}

export async function verifyApi() {
  return apiRequest("/api/auth/verify", "GET");
}

export async function fetchUsers() {
  return apiRequest("/api/users", "GET");
}

export async function getOrCreateConversation(userId: string) {
  return apiRequest(`/api/conversations?userId=${encodeURIComponent(userId)}`, "GET");
}

export async function fetchMessages(
  conversationId: string,
  limit: number = 50,
  offset: number = 0,
) {
  const query = new URLSearchParams({
    conversationId,
    limit: limit.toString(),
    offset: offset.toString(),
  });
  return apiRequest(`/api/messages?${query}`, "GET");
}

export async function updatePublicKey(publicKey: string) {
  return apiRequest("/api/user/public-key", "POST", { publicKey });
}

export async function getUserPublicKey(userId: string) {
  return apiRequest(`/api/user/public-key?userId=${encodeURIComponent(userId)}`, "GET");
}

export async function storeEncryptedPrivateKey(encryptedKeyData: {
  encryptedKey: string;
  salt: string;
  iv: string;
}) {
  return apiRequest("/api/user/encrypted-private-key", "POST", encryptedKeyData);
}

export async function fetchEncryptedPrivateKey() {
  return apiRequest("/api/user/encrypted-private-key", "GET");
}

export async function storeConversationKeyOnServer(
  conversationId: string,
  encryptedKeyData: {
    encryptedKey: string;
    salt: string;
    iv: string;
  },
) {
  return apiRequest("/api/user/conversation-keys", "POST", {
    conversationId,
    ...encryptedKeyData,
  });
}

export async function fetchConversationKeysFromServer() {
  return apiRequest("/api/user/conversation-keys", "GET");
}
