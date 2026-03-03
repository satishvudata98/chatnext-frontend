import { useCallback, useEffect, useRef, useState } from "react";
import type { FC, FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import UserList from "../components/UserList";
import ChatWindow from "../components/ChatWindow";
import { config } from "../config/config";
import {
  fetchUsers,
  getOrCreateConversation,
  updatePublicKey,
  fetchEncryptedPrivateKey,
  storeEncryptedPrivateKey,
  searchUsersByUsername,
  sendBuddyRequest,
  fetchIncomingBuddyRequests,
  respondToBuddyRequest,
} from "../api/api";
import {
  initializeE2EE,
  getUserPublicKey,
  restoreKeyPairFromServer,
  loadUserKeyPair,
  storeUserKeyPair,
  encryptPrivateKeyWithPassword,
} from "../utils/crypto";
import { useAuth } from "../context/AuthContext";
import "../styles/chat.css";

interface User {
  id: string;
  username: string;
  email: string;
  online?: boolean;
  last_seen?: number;
  public_key?: string;
}

interface IncomingBuddyRequest {
  id: string;
  requester_id: string;
  receiver_id: string;
  status: string;
  created_at: number;
  requester: User;
}

const Chat: FC = (): JSX.Element | null => {
  const navigate = useNavigate();
  const { user, token, logout } = useAuth();

  const [users, setUsers] = useState<User[]>([]);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedConversationId, setSelectedConversationId] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState("connecting");
  const [error, setError] = useState("");
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [showMobileChat, setShowMobileChat] = useState(false);
  const [unreadCounts, setUnreadCounts] = useState<Map<string, number>>(new Map());
  const [e2eeReady, setE2eeReady] = useState(false);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const [passphraseMode, setPassphraseMode] = useState<"setup" | "restore">("setup");
  const [pendingBackupData, setPendingBackupData] = useState<{
    encryptedKey: string;
    salt: string;
    iv: string;
    publicKey: string;
  } | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [passphraseError, setPassphraseError] = useState("");
  const [incomingBuddyRequests, setIncomingBuddyRequests] = useState<IncomingBuddyRequest[]>([]);
  const [buddySearchResults, setBuddySearchResults] = useState<User[]>([]);
  const [searchingBuddies, setSearchingBuddies] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef<number>(0);
  const selectionRequestIdRef = useRef<number>(0);
  const maxReconnectAttempts = 5;
  const intentionalCloseRef = useRef<boolean>(false);

  const loadBuddyUsers = useCallback(async (): Promise<void> => {
    const data = await fetchUsers() as { users?: User[] };
    const nextUsers = data.users || [];
    setUsers(nextUsers);
    setSelectedUser((previousSelectedUser) => {
      if (!previousSelectedUser) return null;
      const stillBuddy = nextUsers.some((nextUser) => nextUser.id === previousSelectedUser.id);
      if (!stillBuddy) {
        setSelectedConversationId(null);
        setShowMobileChat(false);
        return null;
      }
      const refreshedSelected = nextUsers.find((nextUser) => nextUser.id === previousSelectedUser.id);
      return refreshedSelected || previousSelectedUser;
    });
  }, []);

  const loadIncomingBuddyRequests = useCallback(async (): Promise<void> => {
    const data = await fetchIncomingBuddyRequests() as { incomingRequests?: IncomingBuddyRequest[] };
    setIncomingBuddyRequests(data.incomingRequests || []);
  }, []);

  const loadBuddyData = useCallback(async (): Promise<void> => {
    await Promise.all([loadBuddyUsers(), loadIncomingBuddyRequests()]);
  }, [loadBuddyUsers, loadIncomingBuddyRequests]);

  const syncPublicKeyToServer = async (): Promise<void> => {
    const publicKey = await getUserPublicKey();
    if (publicKey) {
      await updatePublicKey(publicKey);
    }
  };

  const openPassphrasePrompt = (
    mode: "setup" | "restore",
    backupData: {
      encryptedKey: string;
      salt: string;
      iv: string;
      publicKey: string;
    } | null = null
  ): void => {
    setPassphraseMode(mode);
    setPendingBackupData(backupData);
    setPassphrase("");
    setConfirmPassphrase("");
    setPassphraseError("");
    setShowPassphrasePrompt(true);
  };

  useEffect(() => {
    if (!token || !user) {
      navigate("/login");
      return;
    }

    (async (): Promise<void> => {
      try {
        setE2eeReady(false);
        const existingKeyPair = await loadUserKeyPair();
        const hasSavedKey = Boolean(existingKeyPair);
        const sessionPassphrase = sessionStorage.getItem("tempPassword");
        let serverBackup: {
          encryptedKey: string;
          salt: string;
          iv: string;
          publicKey: string;
        } | null = null;

        try {
          const encryptedData = await fetchEncryptedPrivateKey();
          const typedData = encryptedData as {
            encryptedKey?: string;
            salt?: string;
            iv?: string;
            publicKey?: string;
          };
          if (typedData.encryptedKey && typedData.salt && typedData.iv && typedData.publicKey) {
            serverBackup = {
              encryptedKey: typedData.encryptedKey,
              salt: typedData.salt,
              iv: typedData.iv,
              publicKey: typedData.publicKey,
            };
          }
        } catch {
          // No backup on server yet.
        }

        const localPublicKey = hasSavedKey ? await getUserPublicKey() : null;

        if (
          hasSavedKey &&
          serverBackup &&
          localPublicKey &&
          localPublicKey !== serverBackup.publicKey
        ) {
          if (!sessionPassphrase) {
            openPassphrasePrompt("restore", serverBackup);
            return;
          }

          const restored = await restoreKeyPairFromServer(
            serverBackup.encryptedKey,
            serverBackup.salt,
            serverBackup.iv,
            serverBackup.publicKey,
            sessionPassphrase
          );
          await storeUserKeyPair(restored);
        }

        if (!hasSavedKey) {
          if (!sessionPassphrase) {
            openPassphrasePrompt(serverBackup ? "restore" : "setup", serverBackup);
            return;
          }

          if (serverBackup) {
            const restored = await restoreKeyPairFromServer(
              serverBackup.encryptedKey,
              serverBackup.salt,
              serverBackup.iv,
              serverBackup.publicKey,
              sessionPassphrase
            );
            await storeUserKeyPair(restored);
          } else {
            const generatedKeyPair = await initializeE2EE();
            const encryptedKeyData = await encryptPrivateKeyWithPassword(
              generatedKeyPair.privateKey,
              sessionPassphrase
            );
            await storeEncryptedPrivateKey(encryptedKeyData);
          }
        } else if (!serverBackup) {
          if (!sessionPassphrase) {
            openPassphrasePrompt("setup");
            return;
          }

          const localKeyPairForBackup = existingKeyPair || await initializeE2EE();
          const encryptedKeyData = await encryptPrivateKeyWithPassword(
            localKeyPairForBackup.privateKey,
            sessionPassphrase
          );
          await storeEncryptedPrivateKey(encryptedKeyData);
        }

        await syncPublicKeyToServer();
        setE2eeReady(true);
      } catch (initError) {
        console.error("E2EE init failed:", initError);
        setError("Failed to initialize encryption");
      }
    })();
  }, [navigate, token, user]);

  const handlePassphraseSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setPassphraseError("");

    if (passphrase.length < 8) {
      setPassphraseError("Passphrase must be at least 8 characters.");
      return;
    }

    if (passphraseMode === "setup" && passphrase !== confirmPassphrase) {
      setPassphraseError("Passphrase confirmation does not match.");
      return;
    }

    try {
      setE2eeReady(false);
      sessionStorage.setItem("tempPassword", passphrase);

      if (passphraseMode === "restore" && pendingBackupData) {
        const restored = await restoreKeyPairFromServer(
          pendingBackupData.encryptedKey,
          pendingBackupData.salt,
          pendingBackupData.iv,
          pendingBackupData.publicKey,
          passphrase
        );
        await storeUserKeyPair(restored);
      } else {
        const localKeyPair = await loadUserKeyPair();
        const keyPair = localKeyPair || await initializeE2EE();
        const encryptedKeyData = await encryptPrivateKeyWithPassword(
          keyPair.privateKey,
          passphrase
        );
        await storeEncryptedPrivateKey(encryptedKeyData);
      }

      await syncPublicKeyToServer();
      setShowPassphrasePrompt(false);
      setPendingBackupData(null);
      setE2eeReady(true);
    } catch (passphraseSubmitError) {
      console.error("Passphrase flow failed:", passphraseSubmitError);
      setPassphraseError(
        passphraseMode === "restore"
          ? "Passphrase is incorrect or key restore failed."
          : "Failed to save encrypted key backup."
      );
    }
  };

  useEffect(() => {
    if (!token || !e2eeReady) return;

    (async (): Promise<void> => {
      setLoadingUsers(true);
      try {
        await loadBuddyData();
      } catch (err) {
        console.error("Error fetching buddy data:", err);
        setError("Failed to load buddies");
      } finally {
        setLoadingUsers(false);
      }
    })();
  }, [token, e2eeReady, loadBuddyData]);

  const handleSearchBuddyUsers = async (username: string): Promise<void> => {
    const trimmed = username.trim();
    if (!trimmed) {
      setBuddySearchResults([]);
      return;
    }

    try {
      setSearchingBuddies(true);
      const data = await searchUsersByUsername(trimmed) as { users?: User[] };
      setBuddySearchResults(data.users || []);
    } catch (searchError) {
      console.error("Buddy search failed:", searchError);
      setError("Failed to search users");
    } finally {
      setSearchingBuddies(false);
    }
  };

  const handleSendBuddyRequest = async (toUserId: string): Promise<void> => {
    try {
      await sendBuddyRequest(toUserId);
      setBuddySearchResults((prev) => prev.filter((candidate) => candidate.id !== toUserId));
    } catch (sendError) {
      console.error("Send buddy request failed:", sendError);
      setError("Failed to send buddy request");
    }
  };

  const handleRespondBuddyRequest = async (requestId: string, action: "accept" | "reject"): Promise<void> => {
    try {
      await respondToBuddyRequest(requestId, action);
      await loadBuddyData();
    } catch (respondError) {
      console.error("Buddy request response failed:", respondError);
      setError("Failed to update buddy request");
    }
  };

  const connectWebSocket = (): void => {
    if (!token || !user || !e2eeReady) return;

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

      const connectionTimeout = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          console.error("WebSocket connection timeout");
          ws.close();
          setError("Connection timeout. Retrying...");
          attemptReconnect();
        }
      }, 5000);

      wsRef.current = ws;

      ws.onopen = () => {
        clearTimeout(connectionTimeout);
        setConnectionStatus("connected");
        setWebsocket(ws);
        setError("");
        reconnectAttemptsRef.current = 0;
        ws.send(JSON.stringify({ type: "connect", token }));
      };

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);

          if (data.type === "user_status") {
            setUsers((prevUsers: User[]): User[] =>
              prevUsers.map((u: User): User =>
                u.id === data.userId ? { ...u, online: data.online } : u
              )
            );
          }

          if (data.type === "message") {
            globalThis.dispatchEvent(
              new CustomEvent("websocket:message", { detail: data })
            );
          }

          if (data.type === "message_delivered") {
            globalThis.dispatchEvent(
              new CustomEvent("websocket:message_delivered", { detail: data })
            );
          }

          if (data.type === "message_seen") {
            globalThis.dispatchEvent(
              new CustomEvent("websocket:message_seen", { detail: data })
            );
          }

          if (data.type === "unread_count_update") {
            setUnreadCounts((prev: Map<string, number>) => {
              const updated = new Map(prev);
              if (data.fromUserId) {
                updated.set(data.fromUserId, data.count);
              }
              return updated;
            });
          }

          if (data.type === "buddy_request_incoming" && data.request) {
            setIncomingBuddyRequests((prev) => {
              const alreadyExists = prev.some((request) => request.id === data.request.id);
              if (alreadyExists) return prev;
              return [data.request as IncomingBuddyRequest, ...prev];
            });
          }

          if (data.type === "buddy_request_updated" && data.status === "ACCEPTED") {
            loadBuddyData().catch((loadError) => {
              console.error("Failed to refresh buddy data:", loadError);
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
        setConnectionStatus("disconnected");
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

  useEffect(() => {
    if (!token || !user || !e2eeReady) return;

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
  }, [token, user, e2eeReady]);

  const handleSelectUser = async (selectedUserData: User): Promise<void> => {
    if (!users.some((u) => u.id === selectedUserData.id)) {
      setError("User is not in your buddy list");
      return;
    }

    const requestId = selectionRequestIdRef.current + 1;
    selectionRequestIdRef.current = requestId;
    setSelectedUser(selectedUserData);
    setSelectedConversationId(null);
    setShowMobileChat(true);

    try {
      const data = await getOrCreateConversation(selectedUserData.id);
      if (selectionRequestIdRef.current !== requestId) {
        return;
      }

      const typedData = data as { conversation: { id: string } };
      const conversationId = typedData.conversation.id;
      setSelectedConversationId(conversationId);

      setUnreadCounts((prev: Map<string, number>) => {
        const updated = new Map(prev);
        updated.delete(selectedUserData.id);
        return updated;
      });

      if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
          type: "message_seen",
          conversationId: conversationId,
          messageIds: []
        }));
      }
    } catch (err) {
      if (selectionRequestIdRef.current !== requestId) {
        return;
      }
      console.error("Error getting conversation:", err);
      setError("Failed to load conversation");
      setShowMobileChat(false);
      setSelectedConversationId(null);
    }
  };

  const handleBackToList = (): void => {
    selectionRequestIdRef.current += 1;
    setShowMobileChat(false);
  };

  const handleLogout = async (): Promise<void> => {
    intentionalCloseRef.current = true;
    if (wsRef.current) {
      wsRef.current.close();
    }
    await logout();
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
          <button onClick={() => setError("")} className="error-close">x</button>
        </div>
      )}

      {showPassphrasePrompt && (
        <div className="e2ee-modal-backdrop">
          <div className="e2ee-modal">
            <h3>{passphraseMode === "restore" ? "Unlock Encrypted Messages" : "Set Backup Passphrase"}</h3>
            <p>
              {passphraseMode === "restore"
                ? "Enter your existing E2EE backup passphrase to restore your private key on this device."
                : "Create an E2EE backup passphrase. Use this same passphrase on every device to restore encrypted messages."}
            </p>
            <form onSubmit={handlePassphraseSubmit} className="e2ee-form">
              <input
                type="password"
                placeholder="E2EE backup passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoFocus
              />
              {passphraseMode === "setup" && (
                <input
                  type="password"
                  placeholder="Confirm passphrase"
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                />
              )}
              {passphraseError && <div className="e2ee-error">{passphraseError}</div>}
              <button type="submit" className="e2ee-submit-btn">
                {passphraseMode === "restore" ? "Unlock Messages" : "Save Passphrase"}
              </button>
            </form>
          </div>
        </div>
      )}

      <div className={`sidebar-wrapper ${showMobileChat ? "hide-mobile" : ""}`}>
        <UserList
          users={users}
          selectedUser={selectedUser}
          onSelect={handleSelectUser}
          loading={loadingUsers}
          currentUser={user}
          connectionStatus={connectionStatus}
          onLogout={handleLogout}
          unreadCounts={unreadCounts}
          incomingBuddyRequests={incomingBuddyRequests}
          buddySearchResults={buddySearchResults}
          searchingBuddies={searchingBuddies}
          onSearchBuddyUsers={handleSearchBuddyUsers}
          onSendBuddyRequest={handleSendBuddyRequest}
          onRespondBuddyRequest={handleRespondBuddyRequest}
        />
      </div>

      <div className={`chat-wrapper ${showMobileChat ? "show-mobile" : ""}`}>
        {!e2eeReady ? (
          <div className="chat-loading">
            <div className="loading-spinner"></div>
            <p>Preparing end-to-end encryption...</p>
          </div>
        ) : connectionStatus === "connected" &&
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
              <div className="empty-icon">Chat</div>
              <h2>ChatNext Web</h2>
              <p>Only confirmed buddies can chat with you.</p>
              <p className="empty-hint">Search users and send a buddy request to start.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Chat;
