import { config } from "../config/config";

// Helper to get Authorization header
function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem("token");
  return {
    "Content-Type": "application/json",
    ...(token && { "Authorization": `Bearer ${token}` })
  };
}

// Helper for API requests with error handling
async function apiRequest<T>(
  endpoint: string,
  method: "GET" | "POST" = "GET",
  body?: unknown
): Promise<T> {
  const url = `${config.apiUrl}${endpoint}`;
  
  const options: RequestInit = {
    method,
    headers: getAuthHeader()
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(url, options);

  if (!res.ok) {
    if (res.status === 401) {
      // Token expired or invalid - redirect to login
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      window.location.href = "/login";
    }

    const errorData = await res.json();
    throw new Error(errorData.message || `HTTP error: ${res.status}`);
  }

  return res.json();
}

// Auth APIs
export async function registerApi(
  username: string,
  email: string,
  password: string
) {
  return apiRequest("/api/auth/register", "POST", {
    username,
    email,
    password
  });
}

export async function loginApi(username: string, password: string) {
  return apiRequest("/api/auth/login", "POST", {
    username,
    password
  });
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