import { config } from "../config/config";

// Helper to decode JWT payload (without verification)
function decodeToken(token: string): any {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

// Helper to check if access token is expired
function isTokenExpired(token: string): boolean {
  const decoded = decodeToken(token);
  if (!decoded || !decoded.exp) return true;
  return decoded.exp * 1000 < Date.now();
}

// Helper to get Authorization header
function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem("accessToken");
  if (token && !isTokenExpired(token)) {
    return {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    };
  }
  return { "Content-Type": "application/json" };
}

// Helper to refresh token
async function refreshToken(): Promise<boolean> {
  const refreshToken = localStorage.getItem("refreshToken");
  if (!refreshToken) return false;

  // Check if refresh token is expired
  if (isTokenExpired(refreshToken)) {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("user");
    globalThis.location.href = "/login";
    return false;
  }

  try {
    const res = await fetch(`${config.apiUrl}/api/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken);
        return true;
      }
    }
  } catch (err) {
    console.error("Token refresh failed:", err);
  }
  return false;
}

// Helper for API requests with error handling and auto-refresh
async function apiRequest<T>(
  endpoint: string,
  method: "GET" | "POST" = "GET",
  body?: unknown,
  retry: boolean = true
): Promise<T> {
  const url = `${config.apiUrl}${endpoint}`;

  const options: RequestInit = {
    method,
    headers: getAuthHeader()
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  let res = await fetch(url, options);

  // If 401 and we haven't retried yet, try refreshing token
  if (res.status === 401 && retry) {
    const refreshed = await refreshToken();
    if (refreshed) {
      // Retry with new token
      options.headers = getAuthHeader();
      res = await fetch(url, options);
    }
  }

  if (!res.ok) {
    if (res.status === 401) {
      // Token refresh failed or invalid, logout
      localStorage.removeItem("accessToken");
      localStorage.removeItem("refreshToken");
      localStorage.removeItem("user");
      globalThis.location.href = "/login";
    }

    const errorData = await res.json();
    throw new Error(errorData.message || `HTTP error: ${res.status}`);
  }

  return res.json();
}

// Auth APIs (don't use apiRequest as no token yet)
export async function registerApi(
  username: string,
  email: string,
  password: string
) {
  const res = await fetch(`${config.apiUrl}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password })
  });

  if (!res.ok) {
    const errorData = await res.json();
    throw new Error(errorData.message || `HTTP error: ${res.status}`);
  }

  return res.json();
}

export async function loginApi(username: string, password: string) {
  const res = await fetch(`${config.apiUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    const errorData = await res.json();
    throw new Error(errorData.message || `HTTP error: ${res.status}`);
  }

  return res.json();
}

export async function verifyApi() {
  return apiRequest("/api/auth/verify", "GET");
}

// Users APIs
export async function fetchUsers() {
  return apiRequest("/api/users", "GET");
}

// Conversation APIs
export async function getOrCreateConversation(userId: string) {
  return apiRequest(`/api/conversations?userId=${encodeURIComponent(userId)}`, "GET");
}

// Messages APIs
export async function fetchMessages(
  conversationId: string,
  limit: number = 50,
  offset: number = 0
) {
  const query = new URLSearchParams({
    conversationId,
    limit: limit.toString(),
    offset: offset.toString()
  });
  return apiRequest(`/api/messages?${query}`, "GET");
}

// E2EE APIs
export async function updatePublicKey(publicKey: string) {
  return apiRequest("/api/user/public-key", "POST", { publicKey });
}

export async function getUserPublicKey(userId: string) {
  return apiRequest(`/api/user/public-key?userId=${encodeURIComponent(userId)}`, "GET");
}