import { useEffect, useRef, useState } from "react";
import type { FC, ChangeEvent, FormEvent } from "react";
import { ArrowLeft, ImagePlus, Send } from "lucide-react";
import {
  fetchMediaDownloadUrl,
  fetchMessages,
  getUserPublicKey,
  uploadEncryptedImageMedia,
} from "../api/api";
import {
  decryptAttachmentBinary,
  decryptMessage,
  encryptAttachmentBinary,
  encryptMessage,
  establishConversationKey,
  loadConversationKeyForDecryption,
} from "../utils/crypto";
import MessageBubble from "./MessageBubble";

interface User {
  id: string;
  username: string;
  email: string;
  online?: boolean;
}

interface ImageMessagePayload {
  type: "image";
  mediaId: string;
  mediaKey: string;
  mediaIv: string;
  mimeType: string;
  fileName?: string;
}

interface Message {
  id: string;
  conversationId: string;
  fromUserId: string;
  fromUsername: string;
  message: string;
  contentType: "text" | "image";
  imageUrl?: string;
  imageFileName?: string;
  encryptedMessage?: unknown;
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

const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(["image/jpeg", "image/jpg", "image/png"]);

function parseDecryptedPayload(rawMessage: string):
  | { contentType: "text"; text: string }
  | { contentType: "image"; text: string; imagePayload: ImageMessagePayload } {
  try {
    const parsed = JSON.parse(rawMessage) as Partial<ImageMessagePayload> & { type?: string };
    if (
      parsed.type === "image" &&
      parsed.mediaId &&
      parsed.mediaKey &&
      parsed.mediaIv &&
      parsed.mimeType
    ) {
      return {
        contentType: "image",
        text: "[Image]",
        imagePayload: {
          type: "image",
          mediaId: parsed.mediaId,
          mediaKey: parsed.mediaKey,
          mediaIv: parsed.mediaIv,
          mimeType: parsed.mimeType,
          fileName: parsed.fileName || "image",
        },
      };
    }
  } catch {
    // Not a structured image payload; keep as text for backward compatibility.
  }

  return {
    contentType: "text",
    text: rawMessage,
  };
}

const ChatWindow: FC<Props> = ({
  user,
  selectedUser,
  conversationId,
  ws,
  onBack,
}: Props): JSX.Element => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [conversationKey, setConversationKey] = useState<CryptoKey | null>(null);
  const [uploadingImage, setUploadingImage] = useState(false);
  const [composerError, setComposerError] = useState("");

  const conversationKeyRef = useRef<CryptoKey | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messageListRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mediaUrlCacheRef = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    conversationKeyRef.current = conversationKey;
  }, [conversationKey]);

  useEffect(() => {
    return () => {
      mediaUrlCacheRef.current.forEach((url) => URL.revokeObjectURL(url));
      mediaUrlCacheRef.current.clear();
    };
  }, []);

  useEffect(() => {
    setComposerError("");
    mediaUrlCacheRef.current.forEach((url) => URL.revokeObjectURL(url));
    mediaUrlCacheRef.current.clear();
  }, [conversationId]);

  const scrollToBottom = (): void => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const resolveDecryptedImageUrl = async (
    imagePayload: ImageMessagePayload,
  ): Promise<string | undefined> => {
    const cached = mediaUrlCacheRef.current.get(imagePayload.mediaId);
    if (cached) return cached;

    const downloadData = await fetchMediaDownloadUrl(imagePayload.mediaId) as {
      success: boolean;
      url: string;
    };

    if (!downloadData.success || !downloadData.url) {
      throw new Error("Missing signed image URL");
    }

    const encryptedRes = await fetch(downloadData.url);
    if (!encryptedRes.ok) {
      throw new Error(`Failed to fetch encrypted image: ${encryptedRes.status}`);
    }

    const encryptedBytes = await encryptedRes.arrayBuffer();
    const decryptedBlob = await decryptAttachmentBinary(
      encryptedBytes,
      imagePayload.mediaKey,
      imagePayload.mediaIv,
      imagePayload.mimeType,
    );
    const objectUrl = URL.createObjectURL(decryptedBlob);
    mediaUrlCacheRef.current.set(imagePayload.mediaId, objectUrl);
    return objectUrl;
  };

  const buildMessageFromDecrypted = async (payload: {
    id: string;
    conversationId: string;
    fromUserId: string;
    fromUsername: string;
    encryptedMessage?: unknown;
    createdAt: number;
    status?: string;
    decryptedMessage: string;
  }): Promise<Message> => {
    const parsedPayload = parseDecryptedPayload(payload.decryptedMessage);
    if (parsedPayload.contentType === "image") {
      let imageUrl: string | undefined;
      try {
        imageUrl = await resolveDecryptedImageUrl(parsedPayload.imagePayload);
      } catch (error) {
        console.error("Failed to decrypt image media:", error);
      }

      return {
        id: payload.id,
        conversationId: payload.conversationId,
        fromUserId: payload.fromUserId,
        fromUsername: payload.fromUsername,
        message: imageUrl ? "[Image]" : "[Failed to load image]",
        contentType: "image",
        imageUrl,
        imageFileName: parsedPayload.imagePayload.fileName,
        encryptedMessage: payload.encryptedMessage,
        isRead: false,
        createdAt: payload.createdAt,
        status: payload.status || "sent",
      };
    }

    return {
      id: payload.id,
      conversationId: payload.conversationId,
      fromUserId: payload.fromUserId,
      fromUsername: payload.fromUsername,
      message: parsedPayload.text,
      contentType: "text",
      encryptedMessage: payload.encryptedMessage,
      isRead: false,
      createdAt: payload.createdAt,
      status: payload.status || "sent",
    };
  };

  useEffect(() => {
    const establishKey = async (): Promise<void> => {
      try {
        let key = await loadConversationKeyForDecryption(conversationId);
        if (key) {
          setConversationKey(key);
          return;
        }

        const publicKeyResponse = await getUserPublicKey(selectedUser.id);
        const publicKeyData = publicKeyResponse as { success: boolean; publicKey: string };
        if (publicKeyData.success && publicKeyData.publicKey) {
          key = await establishConversationKey(
            conversationId,
            publicKeyData.publicKey,
          );
        } else {
          console.warn(`[KEY SETUP] Failed to get public key for user ${selectedUser.id}`);
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

  useEffect(() => {
    const handleWebSocketMessage = async (event: Event): Promise<void> => {
      const customEvent = event as CustomEvent<{
        type: string;
        conversationId: string;
        id: string;
        fromUserId: string;
        fromUsername: string;
        encryptedMessage: unknown;
        createdAt: number;
        status?: string;
      }>;
      const data = customEvent.detail;

      if (data.type === "message" && data.conversationId === conversationId) {
        const decryptWithRetry = async (retries = 0, maxRetries = 10): Promise<string> => {
          if (conversationKeyRef.current && data.encryptedMessage) {
            try {
              return await decryptMessage(data.encryptedMessage as never, conversationKeyRef.current);
            } catch (error) {
              console.error("Failed to decrypt incoming message:", error);
              return "[Failed to decrypt]";
            }
          }
          if (retries < maxRetries) {
            await new Promise((resolve) => setTimeout(resolve, 100));
            return decryptWithRetry(retries + 1, maxRetries);
          }
          return "[Encrypted message]";
        };

        const decryptedMessage = await decryptWithRetry();
        const builtMessage = await buildMessageFromDecrypted({
          id: data.id,
          conversationId: data.conversationId,
          fromUserId: data.fromUserId,
          fromUsername: data.fromUsername,
          encryptedMessage: data.encryptedMessage,
          createdAt: data.createdAt,
          status: data.status,
          decryptedMessage,
        });

        setMessages((prev: Message[]): Message[] => {
          let replaced = false;
          const updatedMessages = prev.map((m) => {
            if (
              m.id.startsWith("temp-") &&
              m.fromUserId === data.fromUserId &&
              m.fromUserId === user.id &&
              !replaced &&
              Math.abs(m.createdAt - data.createdAt) < 10
            ) {
              replaced = true;
              return builtMessage;
            }
            return m;
          });

          const alreadyExists = updatedMessages.some((m) => m.id === data.id);
          if (!replaced && !alreadyExists) {
            updatedMessages.push(builtMessage);
          }
          updatedMessages.sort((a, b) => a.createdAt - b.createdAt);
          return updatedMessages;
        });
      }
    };

    const handleMessageDelivered = (event: Event): void => {
      const customEvent = event as CustomEvent<{
        messageId: string;
        conversationId: string;
      }>;
      const data = customEvent.detail;

      if (data.conversationId === conversationId) {
        setMessages((prev: Message[]): Message[] =>
          prev.map((msg: Message): Message =>
            msg.id === data.messageId ? { ...msg, status: "delivered" } : msg,
          ),
        );
      }
    };

    const handleMessageSeen = (event: Event): void => {
      const customEvent = event as CustomEvent<{
        conversationId: string;
        messageIds: string[];
      }>;
      const data = customEvent.detail;

      if (data.conversationId === conversationId) {
        setMessages((prev: Message[]): Message[] =>
          prev.map((msg: Message): Message => {
            if (!msg.id.startsWith("temp-") && data.messageIds.length > 0) {
              return data.messageIds.includes(msg.id)
                ? { ...msg, status: "seen" }
                : msg;
            }
            if (data.messageIds.length === 0) {
              return { ...msg, status: "seen" };
            }
            return msg;
          }),
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

  useEffect(() => {
    const loadMessages = async (): Promise<void> => {
      if (!conversationKey) return;

      setLoading(true);
      try {
        const data = await fetchMessages(conversationId);
        const typedData = data as { success: boolean; messages: any[] };
        if (typedData.success && typedData.messages) {
          const transformedMessages = await Promise.all(
            typedData.messages.map(async (msg: any): Promise<Message> => {
              let decryptedMessage = "[Encrypted message]";
              if (msg.encrypted_message) {
                try {
                  const encryptedData = typeof msg.encrypted_message === "string"
                    ? JSON.parse(msg.encrypted_message)
                    : msg.encrypted_message;
                  decryptedMessage = await decryptMessage(encryptedData, conversationKey);
                } catch (error) {
                  console.error(`Failed to decrypt message ${msg.id}:`, error);
                  decryptedMessage = "[Failed to decrypt]";
                }
              }

              return buildMessageFromDecrypted({
                id: msg.id,
                conversationId: msg.conversation_id,
                fromUserId: msg.from_user_id,
                fromUsername: msg.users?.username || "Unknown",
                encryptedMessage: msg.encrypted_message,
                createdAt: msg.created_at,
                status: msg.status || "sent",
                decryptedMessage,
              });
            }),
          );

          transformedMessages.sort((a, b) => a.createdAt - b.createdAt);
          setMessages(transformedMessages);

          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: "message_seen",
              conversationId,
              messageIds: [],
            }));
          }
        }
      } catch (err) {
        console.error("Error fetching messages:", err);
      } finally {
        setLoading(false);
      }
    };

    loadMessages();
  }, [conversationId, ws, conversationKey]);

  const sendTextMessage = async (e?: FormEvent<HTMLFormElement>): Promise<void> => {
    if (e) e.preventDefault();
    if (!input.trim() || !selectedUser || !conversationKey) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setComposerError("Connection lost. Reconnect and try again.");
      return;
    }

    const messageToSend = input.trim();
    const now = Math.floor(Date.now() / 1000);
    const tempId = `temp-${Date.now()}`;

    let encryptedMessage;
    try {
      encryptedMessage = await encryptMessage(messageToSend, conversationKey, conversationId);
    } catch (error) {
      console.error("Failed to encrypt message:", error);
      return;
    }

    const optimisticMessage: Message = {
      id: tempId,
      conversationId,
      fromUserId: user.id,
      fromUsername: user.username,
      message: messageToSend,
      contentType: "text",
      isRead: false,
      createdAt: now,
    };

    setMessages((prev: Message[]): Message[] => [...prev, optimisticMessage]);
    setInput("");
    setComposerError("");

    try {
      ws.send(JSON.stringify({
        type: "message",
        conversationId,
        toUserId: selectedUser.id,
        encryptedMessage,
      }));
    } catch (error) {
      console.error("Error sending message:", error);
      setMessages((prev: Message[]): Message[] => prev.filter((m) => m.id !== tempId));
      setInput(messageToSend);
    }
  };

  const handleImageSelected = async (event: ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !conversationKey || !selectedUser) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setComposerError("Connection lost. Reconnect and try again.");
      return;
    }

    if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
      setComposerError("Only JPG, JPEG, or PNG files are allowed.");
      return;
    }

    if (file.size > MAX_IMAGE_SIZE_BYTES) {
      setComposerError("Image is too large. Maximum size is 5MB.");
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const tempId = `temp-${Date.now()}`;
    const localPreviewUrl = URL.createObjectURL(file);
    setUploadingImage(true);
    setComposerError("");

    try {
      const fileBytes = await file.arrayBuffer();
      const encryptedBinary = await encryptAttachmentBinary(fileBytes);
      const uploadResponse = await uploadEncryptedImageMedia({
        conversationId,
        fileName: file.name,
        mimeType: file.type,
        encryptedBytes: encryptedBinary.encryptedBytes,
      }) as { success: boolean; mediaId: string };

      if (!uploadResponse.success || !uploadResponse.mediaId) {
        throw new Error("Image upload failed");
      }

      mediaUrlCacheRef.current.set(uploadResponse.mediaId, localPreviewUrl);

      const imagePayload: ImageMessagePayload = {
        type: "image",
        mediaId: uploadResponse.mediaId,
        mediaKey: encryptedBinary.keyBase64,
        mediaIv: encryptedBinary.ivBase64,
        mimeType: file.type,
        fileName: file.name,
      };

      const encryptedMessage = await encryptMessage(
        JSON.stringify(imagePayload),
        conversationKey,
        conversationId,
      );

      const optimisticImageMessage: Message = {
        id: tempId,
        conversationId,
        fromUserId: user.id,
        fromUsername: user.username,
        message: "[Image]",
        contentType: "image",
        imageUrl: localPreviewUrl,
        imageFileName: file.name,
        isRead: false,
        createdAt: now,
      };

      setMessages((prev: Message[]): Message[] => [...prev, optimisticImageMessage]);

      ws.send(JSON.stringify({
        type: "message",
        conversationId,
        toUserId: selectedUser.id,
        encryptedMessage,
      }));
    } catch (error) {
      URL.revokeObjectURL(localPreviewUrl);
      setMessages((prev: Message[]): Message[] => prev.filter((m) => m.id !== tempId));
      console.error("Failed to send encrypted image:", error);
      setComposerError("Failed to send encrypted image.");
    } finally {
      setUploadingImage(false);
    }
  };

  const formatTime = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    const today = new Date();

    if (date.toDateString() === today.toDateString()) {
      return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
    }

    return date.toLocaleDateString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
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
              contentType={m.contentType}
              imageUrl={m.imageUrl}
              imageFileName={m.imageFileName}
              timestamp={m.createdAt}
              username={m.fromUsername}
              formatTime={formatTime}
              status={m.status}
            />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      <form className="input-area" onSubmit={sendTextMessage}>
        <button
          type="button"
          className="attach-btn"
          onClick={() => fileInputRef.current?.click()}
          disabled={loading || uploadingImage || !conversationKey}
          aria-label="Attach image"
        >
          <ImagePlus size={20} />
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/jpeg,image/jpg,image/png"
          onChange={handleImageSelected}
          className="hidden-file-input"
        />
        <input
          type="text"
          value={input}
          onChange={(e: ChangeEvent<HTMLInputElement>): void => setInput(e.target.value)}
          placeholder={uploadingImage ? "Uploading encrypted image..." : "Type a message"}
          disabled={loading || uploadingImage}
          maxLength={1000}
          className="message-input"
          ref={inputRef}
        />
        <button
          type="submit"
          disabled={!input.trim() || loading || uploadingImage || !conversationKey}
          className="send-btn"
          aria-label="Send message"
        >
          <Send size={20} />
        </button>
      </form>
      {composerError && <div className="composer-error">{composerError}</div>}
    </div>
  );
};

export default ChatWindow;
