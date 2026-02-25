import { useEffect, useRef, useState, useMemo } from "react";
import type { FC } from "react";
import { useNavigate } from "react-router";
import UserList from "../components/UserList";
import ChatWindow from "../components/ChatWindow";
import { config } from "../config/config";
import { fetchUsers, getOrCreateConversation, updatePublicKey, fetchEncryptedPrivateKey } from "../api/api";
import { initializeE2EE, getUserPublicKey, restoreKeyPairFromServer, storeUserKeyPair } from "../utils/crypto";
import "../styles/chat.css";

interface User {
  id: string;
  username: string;
  email: string;
  online: boolean;
  last_seen?: number;
  public_key?: string;
}

const Chat: FC = (): JSX.Element | null => {
  const navigate = useNavigate();
  
  // Initialize from localStorage only once using useMemo
  const token = useMemo(() => localStorage.getItem("accessToken"), []);
  const user = useMemo(() => {
    const userStr = localStorage.getItem("user");
    return userStr ? JSON.parse(userStr) : null;
  }, []);
  
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedConversationId, setSelectedConversationId] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState("connecting");
  const [error, setError] = useState("");
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [showMobileChat, setShowMobileChat] = useState(false);
  const [unreadCounts, setUnreadCounts] = useState<Map<string, number>>(new Map());
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef<number>(0);
  const maxReconnectAttempts = 5;
  const intentionalCloseRef = useRef<boolean>(false);
  
  // Redirect to login if not authenticated
  useEffect(() => {
    if (!token || !user) {
      navigate("/login");
      return;
    }

    (async (): Promise<void> => {
      try {
        // Check if we need to restore encrypted private key from server
        let keyPair = await initializeE2EE();
        const hasSavedKey = localStorage.getItem("e2ee_user_keypair");
        if (!hasSavedKey) {
          const password = sessionStorage.getItem("tempPassword");
          if (password) {
            try {
              const encryptedData = await fetchEncryptedPrivateKey();
              const typedData = encryptedData as { 
                success?: boolean; 
                encryptedKey?: string; 
                salt?: string; 
                iv?: string;
                publicKey?: string;
              };
              if (typedData.encryptedKey && typedData.salt && typedData.iv && typedData.publicKey) {
                keyPair = await restoreKeyPairFromServer(
                  typedData.encryptedKey,
                  typedData.salt,
                  typedData.iv,
                  typedData.publicKey,
                  password
                );
                await storeUserKeyPair(keyPair);
              }
            } catch (error) {
              // This is okay - we just generated a new one above
            }
            sessionStorage.removeItem("tempPassword");
          }
        }
        const publicKey = await getUserPublicKey();
        if (publicKey) {
          await updatePublicKey(publicKey);
        }
      } catch (error) {
        setError("Failed to initialize encryption");
      }
    })();
  }, [navigate, token, user]);
  
  // Fetch users list
  useEffect(() => {
    if (!token) return;
    
    (async (): Promise<void> => {
      setLoadingUsers(true);
      try {
        const data = await fetchUsers();
        const typedData = data as { users: User[] };
        setUsers(typedData.users || []);
      } catch (err) {
        console.error("Error fetching users:", err);
        setError("Failed to load users");
      } finally {
        setLoadingUsers(false);
      }
    })();
  }, [token]);
  
  const connectWebSocket = (): void => {
    if (!token || !user) return;
    
    // Close any existing connection first
    if (wsRef.current) {
      try {
        intentionalCloseRef.current = true;
        if (
          wsRef.current.readyState === WebSocket.OPEN ||
          wsRef.current.readyState === WebSocket.CONNECTING
        ) {
          wsRef.current.onopen = null;
          wsRef.current.onclose = null;
          wsRef.current.onerror = null;
          wsRef.current.onmessage = null;
          wsRef.current.close(1000, "Reconnecting");
        }
      } catch (closeErr) {
        console.error("Error closing old WebSocket:", closeErr);
      }
      wsRef.current = null;
      intentionalCloseRef.current = false;
    }
    
    try {
      const wsUrl = config.getWebSocketUrl();
      const ws = new WebSocket(wsUrl);
      
      // Set a connection timeout
      const connectionTimeout = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          console.error("WebSocket connection timeout");
          ws.close();
          setError("Connection timeout. Retrying...");
          attemptReconnect();
        }
      }, 5000); // 5 second timeout
      
      wsRef.current = ws;
      
      ws.onopen = () => {
        clearTimeout(connectionTimeout);
        console.log("WebSocket connected");
        setConnectionStatus("connected");
        setWebsocket(ws);
        setError("");
        reconnectAttemptsRef.current = 0;
        
        // Send authentication with token
        ws.send(JSON.stringify({ type: "connect", token }));
      };
      
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          
          if (data.type === "connected") {
            console.log("Authenticated with server");
          }
          
          if (data.type === "user_status") {
            // Update user online status
            setUsers((prevUsers: User[]): User[] =>
              prevUsers.map((u: User): User =>
                u.id === data.userId ? { ...u, online: data.online } : u
              )
            );
          }
          
          if (data.type === "message") {
            // Message will be handled by ChatWindow component
            // Dispatch custom event so ChatWindow can update
            globalThis.dispatchEvent(
              new CustomEvent("websocket:message", { detail: data })
            );
          }

          if (data.type === "message_delivered") {
            // Message delivery status update
            globalThis.dispatchEvent(
              new CustomEvent("websocket:message_delivered", { detail: data })
            );
          }

          if (data.type === "message_seen") {
            // Message seen status update
            globalThis.dispatchEvent(
              new CustomEvent("websocket:message_seen", { detail: data })
            );
          }

          if (data.type === "unread_count_update") {
            // Update unread count for conversation, keyed by the sender's user ID
            setUnreadCounts((prev: Map<string, number>) => {
              const updated = new Map(prev);
              if (data.fromUserId) {
                updated.set(data.fromUserId, data.count);
              }
              return updated;
            });
          }
          
          if (data.type === "error") {
            console.error("Server error:", data.message);
            setError(data.message);
          }
        } catch (err) {
          console.error("Error parsing message:", err);
        }
      };
      
      ws.onerror = (err: Event) => {
        console.error("WebSocket error:", err);
        setConnectionStatus("error");
        setError("Connection error. Reconnecting...");
      };
      
      ws.onclose = () => {
        console.log("WebSocket closed");
        setConnectionStatus("disconnected");
        
        // Only attempt to reconnect if it wasn't an intentional close
        if (!intentionalCloseRef.current) {
          attemptReconnect();
        }
      };
    } catch (err) {
      console.error("WebSocket connection failed:", err);
      setError("Failed to connect");
      attemptReconnect();
    }
  };
  
  const attemptReconnect = () => {
    if (reconnectAttemptsRef.current >= maxReconnectAttempts) {
      setError("Could not connect to server. Please refresh the page.");
      return;
    }
    
    reconnectAttemptsRef.current += 1;
    const delay = Math.min(
      1000 * Math.pow(2, reconnectAttemptsRef.current - 1),
      10000
    );
    
    reconnectTimeoutRef.current = setTimeout(() => {
      setConnectionStatus("reconnecting");
      connectWebSocket();
    }, delay);
  };
  
  // Connect WebSocket on mount
  useEffect(() => {
    if (!token || !user) return;
    
    connectWebSocket();
    
    return () => {
      intentionalCloseRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      
      if (wsRef.current) {
        try {
          wsRef.current.onopen = null;
          wsRef.current.onclose = null;
          wsRef.current.onerror = null;
          wsRef.current.onmessage = null;
          if (
            wsRef.current.readyState === WebSocket.OPEN ||
            wsRef.current.readyState === WebSocket.CONNECTING
          ) {
            wsRef.current.close(1000, "Cleanup");
          }
        } catch (err) {
          console.error("Error cleaning up WebSocket:", err);
        }
        wsRef.current = null;
      }
    };
  }, [token, user]);
  
  // Handle user selection
  const handleSelectUser = async (
    selectedUserData: User
  ): Promise<void> => {
    setSelectedUser(selectedUserData);
    setShowMobileChat(true);
    try {
      const data = await getOrCreateConversation(selectedUserData.id);
      const typedData = data as { conversation: { id: string } };
      const conversationId = typedData.conversation.id;
      setSelectedConversationId(conversationId);
      
      // Clear unread count for this user
      setUnreadCounts((prev: Map<string, number>) => {
        const updated = new Map(prev);
        updated.delete(selectedUserData.id);
        return updated;
      });

      // Notify backend that user is viewing this conversation
      if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
          type: "message_seen",
          conversationId: conversationId,
          messageIds: []
        }));
      }
    } catch (err) {
      console.error("Error getting conversation:", err);
      setError("Failed to load conversation");
    }
  };
  
  const handleBackToList = (): void => {
    setShowMobileChat(false);
  };
  
  const handleLogout = (): void => {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("user");
    intentionalCloseRef.current = true;
    if (wsRef.current) {
      wsRef.current.close();
    }
    navigate("/");
  };
  
  if (!token || !user) {
    return null;
  }
  
  return (
    <div className="chat-container">
      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={() => setError("")} className="error-close">×</button>
        </div>
      )}
      
      <div
        className={`sidebar-wrapper ${showMobileChat ? "hide-mobile" : ""}`}
      >
        <UserList
          users={users}
          selectedUser={selectedUser}
          onSelect={handleSelectUser}
          loading={loadingUsers}
          currentUser={user}
          connectionStatus={connectionStatus}
          onLogout={handleLogout}
          unreadCounts={unreadCounts}
        />
      </div>
      
      <div
        className={`chat-wrapper ${showMobileChat ? "show-mobile" : ""}`}
      >
        {connectionStatus === "connected" &&
        selectedUser &&
        selectedConversationId &&
        websocket ? (
          <ChatWindow
            user={user}
            selectedUser={selectedUser}
            conversationId={selectedConversationId}
            ws={websocket}
            onBack={handleBackToList}
          />
        ) : selectedUser ? (
          <div className="chat-loading">
            <div className="loading-spinner"></div>
            <p>Loading chat...</p>
          </div>
        ) : (
          <div className="chat-empty">
            <div className="empty-content">
              <div className="empty-icon">💬</div>
              <h2>ChatNext Web</h2>
              <p>
                Send and receive messages in real-time.
              </p>
              <p className="empty-hint">
                Select a contact from the sidebar to start chatting
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Chat;