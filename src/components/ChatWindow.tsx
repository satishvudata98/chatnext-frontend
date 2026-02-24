import { useEffect, useState, useRef } from "react";
import type { FC, ChangeEvent, FormEvent } from "react";
import { ArrowLeft, Send } from "lucide-react";
import { fetchMessages, getUserPublicKey } from "../api/api";
import { establishConversationKey, encryptMessage, decryptMessage, loadConversationKeyForDecryption } from "../utils/crypto";
import MessageBubble from "./MessageBubble";

interface User {
  id: string;
  username: string;
  email: string;
  online?: boolean;
}

interface Message {
  id: string;
  conversationId: string;
  fromUserId: string;
  fromUsername: string;
  message: string; // This will be the decrypted message
  encryptedMessage?: any; // Raw encrypted data from server
  isRead: boolean;
  createdAt: number;
  status?: string;
}

interface Props {
  user: User;
  selectedUser: User;
  conversationId: string;
  ws: WebSocket;
  onBack: () => void;
}

const ChatWindow: FC<Props> = (props: Props): JSX.Element => {
  const { user, selectedUser, conversationId, ws, onBack } = props;
  
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [conversationKey, setConversationKey] = useState<CryptoKey | null>(null);
  const conversationKeyRef = useRef<CryptoKey | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messageListRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  // Keep conversationKeyRef in sync with state to avoid closure issues in WebSocket handler
  useEffect(() => {
    conversationKeyRef.current = conversationKey;
  }, [conversationKey]);
  
  const scrollToBottom = (): void => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };
  
  useEffect(() => {
    scrollToBottom();
  }, [messages]);
  
  // Establish conversation encryption key
  useEffect(() => {
    const establishKey = async (): Promise<void> => {
      try {
        // Check if we already have a key for this conversation
        let key = await loadConversationKeyForDecryption(conversationId);
        if (key) {
          setConversationKey(key);
          return;
        }
        
        // Get the other user's public key
        const publicKeyResponse = await getUserPublicKey(selectedUser.id);
        const publicKeyData = publicKeyResponse as { success: boolean; publicKey: string };
        if (publicKeyData.success && publicKeyData.publicKey) {
          key = await establishConversationKey(
            conversationId,
            publicKeyData.publicKey
          );
        } else {
          console.warn(`[KEY SETUP] ✗ Failed to get public key for user ${selectedUser.id}`);
        }
        setConversationKey(key);
      } catch (error) {
        console.error("Failed to establish conversation key:", error);
      }
    };

    if (selectedUser) {
      establishKey();
    }
  }, [conversationId, selectedUser]);
  
  // Listen for incoming messages from WebSocket
  useEffect(() => {
    const handleWebSocketMessage = async (event: Event): Promise<void> => {
      const customEvent = event as CustomEvent<{
        type: string;
        conversationId: string;
        id: string;
        fromUserId: string;
        fromUsername: string;
        encryptedMessage: any;
        createdAt: number;
        status?: string;
      }>;
      const data = customEvent.detail;

      if (data.type === "message" && data.conversationId === conversationId) {
        
        // Decrypt the message with retry logic for key establishment
        const decryptWithRetry = async (retries = 0, maxRetries = 10): Promise<string> => {
          
          if (conversationKeyRef.current && data.encryptedMessage) {
            try {
              const result = await decryptMessage(data.encryptedMessage, conversationKeyRef.current);
              return result;
            } catch (error) {
              console.error("[DECRYPT RETRY] ✗ Failed to decrypt message:", error);
              return "[Failed to decrypt]";
            }
          } else if (retries < maxRetries) {
            await new Promise(resolve => setTimeout(resolve, 100));
            return decryptWithRetry(retries + 1, maxRetries);
          } else {
            // Max retries reached, show encrypted placeholder
            console.warn(`[DECRYPT RETRY] ✗ Max retries reached, key still not available`);
            return "[Encrypted message]";
          }
        };

        const decryptedMessage = await decryptWithRetry();

        setMessages((prev: Message[]): Message[] => {
          // Check if this is a confirmation of our own message (replace temp ID)
          const tempMessageIndex = prev.findIndex(
            (m) =>
              m.id.startsWith("temp-") &&
              m.fromUserId === user.id
          );

          if (tempMessageIndex !== -1) {
            // Replace temp message with confirmed message from server
            const updatedMessages = [...prev];
            updatedMessages[tempMessageIndex] = {
              id: data.id,
              conversationId: data.conversationId,
              fromUserId: data.fromUserId,
              fromUsername: data.fromUsername,
              message: decryptedMessage,
              encryptedMessage: data.encryptedMessage,
              isRead: false,
              createdAt: data.createdAt,
              status: data.status || "sent"
            };
            return updatedMessages;
          } else {
            // New message from other user
            const newMessage: Message = {
              id: data.id,
              conversationId: data.conversationId,
              fromUserId: data.fromUserId,
              fromUsername: data.fromUsername,
              message: decryptedMessage,
              encryptedMessage: data.encryptedMessage,
              isRead: false,
              createdAt: data.createdAt,
              status: data.status || "sent"
            };
            return [...prev, newMessage];
          }
        });
      }
    };

    const handleMessageDelivered = (event: Event): void => {
      const customEvent = event as CustomEvent<{
        messageId: string;
        conversationId: string;
        deliveredAt: number;
      }>;
      const data = customEvent.detail;

      if (data.conversationId === conversationId) {
        setMessages((prev: Message[]): Message[] =>
          prev.map((msg: Message): Message =>
            msg.id === data.messageId ? { ...msg, status: "delivered" } : msg
          )
        );
      }
    };

    const handleMessageSeen = (event: Event): void => {
      const customEvent = event as CustomEvent<{
        conversationId: string;
        userId: string;
        seenAt: number;
        messageIds: string[];
      }>;
      const data = customEvent.detail;

      if (data.conversationId === conversationId) {
        setMessages((prev: Message[]): Message[] =>
          prev.map((msg: Message): Message => {
            // Update messages that were marked as seen by the other user
            if (!msg.id.startsWith("temp-") && data.messageIds.length > 0) {
              return data.messageIds.includes(msg.id)
                ? { ...msg, status: "seen" }
                : msg;
            } else if (data.messageIds.length === 0) {
              // All messages in conversation marked as seen
              return { ...msg, status: "seen" };
            }
            return msg;
          })
        );
      }
    };
    
    globalThis.addEventListener("websocket:message", handleWebSocketMessage);
    globalThis.addEventListener("websocket:message_delivered", handleMessageDelivered);
    globalThis.addEventListener("websocket:message_seen", handleMessageSeen);

    return (): void => {
      globalThis.removeEventListener("websocket:message", handleWebSocketMessage);
      globalThis.removeEventListener("websocket:message_delivered", handleMessageDelivered);
      globalThis.removeEventListener("websocket:message_seen", handleMessageSeen);
    };
  }, [conversationId, user.id]);
  
  // Load message history when conversation is selected
  useEffect(() => {
    const loadMessages = async (): Promise<void> => {
      
      if (!conversationKey) {
        return;
      }

      setLoading(true);
      try {
        const data = await fetchMessages(conversationId);
        const typedData = data as { success: boolean; messages: any[] };
        if (typedData.success && typedData.messages) {
          // Transform backend message format to our format and decrypt
          const transformedMessages = await Promise.all(
            typedData.messages.map(async (msg: any) => {
              let decryptedMessage = "[Encrypted message]";
              if (msg.encrypted_message) {
                try {
                  const encryptedData = typeof msg.encrypted_message === 'string'
                    ? JSON.parse(msg.encrypted_message)
                    : msg.encrypted_message;
                  decryptedMessage = await decryptMessage(encryptedData, conversationKey);
                } catch (error) {
                  console.error(`[LOAD MESSAGES] ✗ Failed to decrypt message ${msg.id}:`, error);
                  decryptedMessage = "[Failed to decrypt]";
                }
              } else {
                console.warn(`[LOAD MESSAGES] ⚠ Message ${msg.id} has no encrypted_message field`);
              }

              return {
                id: msg.id,
                conversationId: msg.conversation_id,
                fromUserId: msg.from_user_id,
                fromUsername: msg.users?.username || "Unknown",
                message: decryptedMessage,
                encryptedMessage: msg.encrypted_message,
                isRead: false,
                createdAt: msg.created_at,
                status: msg.status || "sent"
              };
            })
          );
          setMessages(transformedMessages);

          // Send message_seen event for all messages in this conversation
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: "message_seen",
              conversationId: conversationId,
              messageIds: []
            }));
          }
        }
      } catch (err) {
        console.error("[LOAD MESSAGES] ✗ Error fetching messages:", err);
      } finally {
        setLoading(false);
      }
    };

    loadMessages();
  }, [conversationId, ws, conversationKey]);
  
  const send = async (e?: FormEvent<HTMLFormElement>): Promise<void> => {
    if (e) {
      e.preventDefault();
    }

    if (!input.trim() || !selectedUser || !conversationKey) return;

    const messageToSend: string = input.trim();
    const now = Math.floor(Date.now() / 1000);
    const tempId = `temp-${Date.now()}`;

    // Encrypt the message
    let encryptedMessage;
    try {
      encryptedMessage = await encryptMessage(messageToSend, conversationKey, conversationId);
    } catch (error) {
      console.error("Failed to encrypt message:", error);
      return;
    }

    // Optimistic update - add message to UI immediately
    const optimisticMessage: Message = {
      id: tempId,
      conversationId,
      fromUserId: user.id,
      fromUsername: user.username,
      message: messageToSend,
      isRead: false,
      createdAt: now
    };

    setMessages((prev: Message[]): Message[] => [...prev, optimisticMessage]);
    setInput("");

    try {
      ws.send(
        JSON.stringify({
          type: "message",
          conversationId,
          toUserId: selectedUser.id,
          encryptedMessage
        })
      );
    } catch (error) {
      console.error("Error sending message:", error);
      // Remove optimistic message on error
      setMessages((prev: Message[]): Message[] =>
        prev.filter((m): boolean => m.id !== tempId)
      );
      // Restore input
      setInput(messageToSend);
    }
  };
  
  // Format timestamp to readable format
  const formatTime = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    const today = new Date();
    
    if (date.toDateString() === today.toDateString()) {
      return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
      });
    }
    
    return date.toLocaleDateString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  };
  
  return (
    <div className="chat-window">
      <div className="chat-header">
        <button className="back-btn" onClick={onBack} aria-label="Back to chats">
          <ArrowLeft size={20} />
        </button>
        <div className="chat-header-avatar">
          {selectedUser.username.charAt(0).toUpperCase()}
        </div>
        <div className="chat-header-info">
          <h3>{selectedUser.username}</h3>
          <span className={`status-text ${selectedUser.online ? "online" : "offline"}`}>
            {selectedUser.online ? "online" : "offline"}
          </span>
        </div>
      </div>
      
      <div className="messages" ref={messageListRef}>
        {loading ? (
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Loading messages...</p>
          </div>
        ) : messages.length === 0 ? (
          <div className="empty-chat">
            <div className="empty-chat-icon">👋</div>
            <p>No messages yet. Say hello!</p>
          </div>
        ) : (
          messages.map((m) => (
            <MessageBubble
              key={m.id}
              isOwn={m.fromUserId === user.id}
              message={m.message}
              timestamp={m.createdAt}
              username={m.fromUsername}
              formatTime={formatTime}
              status={m.status}
            />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>
      
      <form className="input-area" onSubmit={send}>
        <input
          type="text"
          value={input}
          onChange={(e: ChangeEvent<HTMLInputElement>): void =>
            setInput(e.target.value)
          }
          placeholder="Type a message"
          disabled={loading}
          maxLength={1000}
          className="message-input"
          ref={inputRef}
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="send-btn"
          aria-label="Send message"
        >
          <Send size={20} />
        </button>
      </form>
    </div>
  );
};

export default ChatWindow;