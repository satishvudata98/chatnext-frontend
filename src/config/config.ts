/**
 * Configuration file for environment variables
 * Uses Vite's import.meta.env to access .env variables
 */

export const config = {
  // API base URL for REST API calls
  apiUrl: import.meta.env.VITE_API_URL || "http://localhost:3000",
  
  // WebSocket URL for real-time messaging
  wsUrl: import.meta.env.VITE_WS_URL || "ws://localhost:3000",
  
  // Derived WebSocket URL with proper protocol
  getWebSocketUrl: (): string => {
    const baseUrl = import.meta.env.VITE_WS_URL || "ws://localhost:3000";
    
    // If running in production with https, ensure wss:// protocol
    if (typeof window !== "undefined" && location.protocol === "https:") {
      return baseUrl.replace(/^ws:/, "wss:");
    }
    
    return baseUrl;
  },
};

export default config;
