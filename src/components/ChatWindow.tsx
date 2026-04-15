import { Fragment, useEffect, useRef, useState } from "react";
import type { ChangeEvent, ComponentPropsWithoutRef, FC } from "react";
import { ArrowLeft, ImagePlus, Pencil, Reply, Send, X } from "lucide-react";
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
import {
  buildImageMessagePayload,
  buildReplyPreviewPayload,
  buildTextMessagePayload,
  parseDecryptedMessagePayload,
} from "../utils/messagePayload";
import type {
  ImageMessagePayload,
  MessageContentType,
  ReplyPreviewPayload,
} from "../utils/messagePayload";

interface User {
  id: string;
  username: string;
  email: string;
  online?: boolean;
  last_seen?: number;
}

interface Message {
  id: string;
  conversationId: string;
  fromUserId: string;
  fromUsername: string;
  message: string;
  contentType: MessageContentType;
  imageUrl?: string;
  imageFileName?: string;
  encryptedMessage?: unknown;
  isRead: boolean;
  createdAt: number;
  status?: string;
  replyToMessageId?: string | null;
  replyPreview?: ReplyPreviewPayload | null;
  editedAt?: number | null;
  editVersion?: number;
}

interface MessageHistoryRow {
  id: string;
  conversation_id: string;
  from_user_id: string;
  content_type?: MessageContentType | null;
  reply_to_message_id?: string | null;
  encrypted_message?: unknown;
  created_at: number;
  edited_at?: number | null;
  edit_version?: number | null;
  status?: string;
  delivered_at?: number | null;
  seen_at?: number | null;
  users?: {
    username?: string | null;
  } | null;
}

interface MessagesResponse {
  success: boolean;
  messages: MessageHistoryRow[];
}

interface MessageEventDetail {
  type: "message";
  conversationId: string;
  id: string;
  clientMessageId?: string;
  fromUserId: string;
  fromUsername: string;
  encryptedMessage: unknown;
  contentType?: MessageContentType;
  replyToMessageId?: string | null;
  createdAt: number;
  editedAt?: number | null;
  editVersion?: number;
  status?: string;
}

interface MessageEditedEventDetail {
  id: string;
  conversationId: string;
  encryptedMessage: unknown;
  contentType?: MessageContentType;
  replyToMessageId?: string | null;
  editedAt?: number | null;
  editVersion?: number;
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
const DAY_MS = 24 * 60 * 60 * 1000;
const MESSAGE_EDIT_WINDOW_SECONDS = 15 * 60;

function getDayKey(unixTimestamp: number): string {
  const date = new Date(unixTimestamp * 1000);
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

function formatDayLabel(unixTimestamp: number): string {
  const messageDate = new Date(unixTimestamp * 1000);
  const today = new Date();
  const messageDay = new Date(
    messageDate.getFullYear(),
    messageDate.getMonth(),
    messageDate.getDate(),
  );
  const todayDay = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const dayDiff = Math.round((todayDay.getTime() - messageDay.getTime()) / DAY_MS);

  if (dayDiff === 0) return "Today";
  if (dayDiff === 1) return "Yesterday";

  if (messageDay.getFullYear() === todayDay.getFullYear()) {
    return messageDay.toLocaleDateString(undefined, {
      day: "numeric",
      month: "long",
    });
  }

  return messageDay.toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

function isMessageEditable(message: Message, userId: string): boolean {
  if (message.fromUserId !== userId) return false;
  if (message.id.startsWith("temp-")) return false;
  if (message.contentType !== "text") return false;
  return Math.floor(Date.now() / 1000) - message.createdAt <= MESSAGE_EDIT_WINDOW_SECONDS;
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
  const [offlineQueue, setOfflineQueue] = useState<string[]>([]);
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const [activeActionMessageId, setActiveActionMessageId] = useState<string | null>(null);

  const conversationKeyRef = useRef<CryptoKey | null>(null);
  const messagesRef = useRef<Message[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messageListRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mediaUrlCacheRef = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    conversationKeyRef.current = conversationKey;
  }, [conversationKey]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    return () => {
      mediaUrlCacheRef.current.forEach((url) => URL.revokeObjectURL(url));
      mediaUrlCacheRef.current.clear();
    };
  }, []);

  useEffect(() => {
    setComposerError("");
    setOfflineQueue([]);
    setReplyingTo(null);
    setEditingMessage(null);
    setActiveActionMessageId(null);
    setInput("");
    mediaUrlCacheRef.current.forEach((url) => URL.revokeObjectURL(url));
    mediaUrlCacheRef.current.clear();
  }, [conversationId]);

  useEffect(() => {
    if (!replyingTo && !editingMessage) return;

    const frameId = globalThis.requestAnimationFrame(() => {
      inputRef.current?.focus();
      const inputElement = inputRef.current;
      if (inputElement) {
        const textLength = inputElement.value.length;
        inputElement.setSelectionRange(textLength, textLength);
      }
    });

    return () => {
      globalThis.cancelAnimationFrame(frameId);
    };
  }, [replyingTo, editingMessage]);

  useEffect(() => {
    const handlePointerDown = (event: PointerEvent): void => {
      const target = event.target as HTMLElement | null;
      if (target?.closest(".message-actions")) return;
      setActiveActionMessageId(null);
    };

    globalThis.addEventListener("pointerdown", handlePointerDown);
    return () => {
      globalThis.removeEventListener("pointerdown", handlePointerDown);
    };
  }, []);

  useEffect(() => {
    const messageList = messageListRef.current;
    if (!messageList) return;

    const handleScroll = (): void => {
      setActiveActionMessageId(null);
    };

    messageList.addEventListener("scroll", handleScroll);
    return () => {
      messageList.removeEventListener("scroll", handleScroll);
    };
  }, []);

  useEffect(() => {
    if (!ws) return;

    const flushQueue = () => {
      if (ws.readyState === WebSocket.OPEN && offlineQueue.length > 0) {
        const queueToFlush = [...offlineQueue];
        setOfflineQueue([]);
        queueToFlush.forEach(payload => {
          try {
            ws.send(payload);
          } catch (e) {
            console.error("Queue flush error", e);
          }
        });
      }
    };

    if (ws.readyState === WebSocket.OPEN) {
      flushQueue();
    } else {
      ws.addEventListener("open", flushQueue);
      return () => ws.removeEventListener("open", flushQueue);
    }
  }, [ws, offlineQueue]);

  const scrollToBottom = (): void => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const sendSeenReceipt = (messageIds: string[]): void => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const uniqueIds = [...new Set(messageIds.filter(Boolean))];
    if (uniqueIds.length === 0) return;

    ws.send(JSON.stringify({
      type: "message_seen",
      conversationId,
      messageIds: uniqueIds,
    }));
  };

  const formatLastActive = (lastSeen?: number): string => {
    if (!lastSeen) return "offline";

    const seenDate = new Date(lastSeen * 1000);
    const now = new Date();
    const seenDay = new Date(seenDate.getFullYear(), seenDate.getMonth(), seenDate.getDate());
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
    const timeText = seenDate.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

    if (seenDay.getTime() === today.getTime()) {
      return `last active today at ${timeText}`;
    }

    if (seenDay.getTime() === yesterday.getTime()) {
      return `last active yesterday at ${timeText}`;
    }

    const hasSameYear = seenDate.getFullYear() === now.getFullYear();
    const dateText = seenDate.toLocaleDateString([], hasSameYear
      ? { day: "numeric", month: "short" }
      : { day: "numeric", month: "short", year: "numeric" });

    return `last active ${dateText} at ${timeText}`;
  };

  const statusLabel = selectedUser.online ? "online" : formatLastActive(selectedUser.last_seen);

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
    editedAt?: number | null;
    editVersion?: number;
    replyToMessageId?: string | null;
    decryptedMessage: string;
  }): Promise<Message> => {
    const parsedPayload = parseDecryptedMessagePayload(payload.decryptedMessage);
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
        replyToMessageId: payload.replyToMessageId ?? parsedPayload.replyPreview?.messageId ?? null,
        replyPreview: parsedPayload.replyPreview,
        editedAt: payload.editedAt ?? null,
        editVersion: payload.editVersion || 0,
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
      replyToMessageId: payload.replyToMessageId ?? parsedPayload.replyPreview?.messageId ?? null,
      replyPreview: parsedPayload.replyPreview,
      editedAt: payload.editedAt ?? null,
      editVersion: payload.editVersion || 0,
      status: payload.status || "sent",
    };
  };

  const openReplyComposer = (message: Message): void => {
    if (message.id.startsWith("temp-")) return;

    setEditingMessage(null);
    setReplyingTo(message);
    setActiveActionMessageId(null);
  };

  const openEditComposer = (message: Message): void => {
    if (!isMessageEditable(message, user.id)) return;

    setReplyingTo(null);
    setEditingMessage(message);
    setInput(message.message);
    setActiveActionMessageId(null);
  };

  const clearComposerContext = (): void => {
    setReplyingTo(null);
    setEditingMessage(null);
    setComposerError("");
  };

  useEffect(() => {
    const establishKey = async (): Promise<void> => {
      if (!selectedUser?.id) return;

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

    establishKey();
  }, [conversationId, selectedUser?.id]);

  useEffect(() => {
    const handleWebSocketMessage = async (event: Event): Promise<void> => {
      const customEvent = event as CustomEvent<MessageEventDetail>;
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
          editedAt: data.editedAt,
          editVersion: data.editVersion,
          replyToMessageId: data.replyToMessageId,
          status: data.status,
          decryptedMessage,
        });

        setMessages((prev: Message[]): Message[] => {
          let replaced = false;
          const updatedMessages = prev.map((m) => {
            if (
              m.id.startsWith("temp-") &&
              data.clientMessageId &&
              m.id === data.clientMessageId &&
              !replaced
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

        if (data.fromUserId !== user.id) {
          sendSeenReceipt([data.id]);
        }
      }
    };

    const handleMessageEdited = async (event: Event): Promise<void> => {
      const customEvent = event as CustomEvent<MessageEditedEventDetail>;
      const data = customEvent.detail;

      if (data.conversationId !== conversationId) return;

      const existingMessage = messagesRef.current.find((message) => message.id === data.id);
      if (!existingMessage || !conversationKeyRef.current || !data.encryptedMessage) {
        return;
      }

      let decryptedMessage = "[Failed to decrypt]";
      try {
        decryptedMessage = await decryptMessage(data.encryptedMessage as never, conversationKeyRef.current);
      } catch (error) {
        console.error("Failed to decrypt edited message:", error);
      }

      const updatedMessage = await buildMessageFromDecrypted({
        id: existingMessage.id,
        conversationId: existingMessage.conversationId,
        fromUserId: existingMessage.fromUserId,
        fromUsername: existingMessage.fromUsername,
        encryptedMessage: data.encryptedMessage,
        createdAt: existingMessage.createdAt,
        editedAt: data.editedAt,
        editVersion: data.editVersion,
        replyToMessageId: data.replyToMessageId ?? existingMessage.replyToMessageId ?? null,
        status: existingMessage.status,
        decryptedMessage,
      });

      setMessages((prevMessages): Message[] =>
        prevMessages.map((message) => (
          message.id === data.id
            ? {
                ...updatedMessage,
                status: message.status,
              }
            : message
        )),
      );

      if (editingMessage?.id === data.id) {
        setEditingMessage(updatedMessage);
      }
    };

    const handleMessageDelivered = (event: Event): void => {
      const customEvent = event as CustomEvent<{
        messageId: string;
        clientMessageId?: string;
        conversationId: string;
      }>;
      const data = customEvent.detail;

      if (data.conversationId === conversationId) {
        setMessages((prev: Message[]): Message[] =>
          prev.map((msg: Message): Message =>
            (msg.id === data.messageId || (data.clientMessageId && msg.id === data.clientMessageId))
              ? { ...msg, id: data.messageId, status: "delivered" }
              : msg,
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
        if (!Array.isArray(data.messageIds) || data.messageIds.length === 0) return;

        setMessages((prev: Message[]): Message[] =>
          prev.map((msg: Message): Message => {
            if (!msg.id.startsWith("temp-")) {
              return data.messageIds.includes(msg.id)
                ? { ...msg, status: "seen" }
                : msg;
            }
            return msg;
          }),
        );
      }
    };

    globalThis.addEventListener("websocket:message", handleWebSocketMessage);
    globalThis.addEventListener("websocket:message_delivered", handleMessageDelivered);
    globalThis.addEventListener("websocket:message_seen", handleMessageSeen);
    globalThis.addEventListener("websocket:message_edited", handleMessageEdited);

    return (): void => {
      globalThis.removeEventListener("websocket:message", handleWebSocketMessage);
      globalThis.removeEventListener("websocket:message_delivered", handleMessageDelivered);
      globalThis.removeEventListener("websocket:message_seen", handleMessageSeen);
      globalThis.removeEventListener("websocket:message_edited", handleMessageEdited);
    };
  }, [conversationId, editingMessage, user.id, ws]);

  useEffect(() => {
    const loadMessages = async (): Promise<void> => {
      if (!conversationKey) return;

      setLoading(true);
      try {
        const data = await fetchMessages(conversationId);
        const typedData = data as MessagesResponse;
        if (typedData.success && typedData.messages) {
          const transformedMessages = await Promise.all(
            typedData.messages.map(async (msg): Promise<Message> => {
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
                editedAt: msg.edited_at,
                editVersion: msg.edit_version || 0,
                replyToMessageId: msg.reply_to_message_id ?? null,
                status: msg.status || "sent",
                decryptedMessage,
              });
            }),
          );

          transformedMessages.sort((a, b) => a.createdAt - b.createdAt);
          setMessages(transformedMessages);

          const unreadIncomingIds = transformedMessages
            .filter((msg) => msg.fromUserId !== user.id && msg.status !== "seen")
            .map((msg) => msg.id);

          sendSeenReceipt(unreadIncomingIds);
        }
      } catch (err) {
        console.error("Error fetching messages:", err);
      } finally {
        setLoading(false);
      }
    };

    loadMessages();
  }, [conversationId, conversationKey, user.id, ws]);

  const buildReplyContext = (): ReplyPreviewPayload | null => {
    if (!replyingTo) return null;
    return buildReplyPreviewPayload(replyingTo);
  };

  const sendTextMessage = async (): Promise<void> => {
    if (!input.trim() || !selectedUser || !conversationKey) return;

    const messageToSend = input.trim();
    const now = Math.floor(Date.now() / 1000);
    const tempId = `temp-${crypto.randomUUID()}`;
    const replyPreview = buildReplyContext();

    let encryptedMessage;
    try {
      encryptedMessage = await encryptMessage(
        buildTextMessagePayload(messageToSend, replyPreview),
        conversationKey,
        conversationId,
      );
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
      replyToMessageId: replyingTo?.id ?? null,
      replyPreview,
      editedAt: null,
      editVersion: 0,
    };

    setMessages((prev: Message[]): Message[] => [...prev, optimisticMessage]);
    setInput("");
    setComposerError("");
    setReplyingTo(null);

    const payload = JSON.stringify({
      type: "message",
      clientMessageId: tempId,
      conversationId,
      toUserId: selectedUser.id,
      contentType: "text",
      replyToMessageId: optimisticMessage.replyToMessageId,
      encryptedMessage,
    });

    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(payload);
      } catch (error) {
        console.error("Error sending message:", error);
        setOfflineQueue((prev) => [...prev, payload]);
      }
    } else {
      setOfflineQueue((prev) => [...prev, payload]);
    }
  };

  const sendEditedMessage = async (): Promise<void> => {
    if (!editingMessage || !input.trim() || !conversationKey) return;
    if (!isMessageEditable(editingMessage, user.id)) {
      setComposerError("This message can no longer be edited.");
      return;
    }

    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setComposerError("Reconnect to edit this message.");
      return;
    }

    try {
      const encryptedMessage = await encryptMessage(
        buildTextMessagePayload(input.trim(), editingMessage.replyPreview ?? null),
        conversationKey,
        conversationId,
      );

      ws.send(JSON.stringify({
        type: "message_edit",
        messageId: editingMessage.id,
        conversationId,
        contentType: "text",
        encryptedMessage,
      }));

      setComposerError("");
      setInput("");
      setEditingMessage(null);
    } catch (error) {
      console.error("Failed to edit message:", error);
      setComposerError("Failed to edit message.");
    }
  };

  const handleImageSelected = async (event: ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !conversationKey || !selectedUser) return;

    if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
      setComposerError("Only JPG, JPEG, or PNG files are allowed.");
      return;
    }

    if (file.size > MAX_IMAGE_SIZE_BYTES) {
      setComposerError("Image is too large. Maximum size is 5MB.");
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const tempId = `temp-${crypto.randomUUID()}`;
    const localPreviewUrl = URL.createObjectURL(file);
    const replyPreview = buildReplyContext();
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
        buildImageMessagePayload(imagePayload, replyPreview),
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
        replyToMessageId: replyingTo?.id ?? null,
        replyPreview,
        editedAt: null,
        editVersion: 0,
      };

      setMessages((prev: Message[]): Message[] => [...prev, optimisticImageMessage]);
      setReplyingTo(null);

      const payload = JSON.stringify({
        type: "message",
        clientMessageId: tempId,
        conversationId,
        toUserId: selectedUser.id,
        contentType: "image",
        replyToMessageId: optimisticImageMessage.replyToMessageId,
        encryptedMessage,
      });

      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(payload);
        } catch (error) {
          console.error("Error sending image message:", error);
          setOfflineQueue((prev) => [...prev, payload]);
        }
      } else {
        setOfflineQueue((prev) => [...prev, payload]);
      }
    } catch (error) {
      URL.revokeObjectURL(localPreviewUrl);
      setMessages((prev: Message[]): Message[] => prev.filter((m) => m.id !== tempId));
      console.error("Failed to process encrypted image:", error);
      setComposerError("Failed to send encrypted image.");
    } finally {
      setUploadingImage(false);
    }
  };

  const formatTime = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const handleComposerSubmit: NonNullable<ComponentPropsWithoutRef<"form">["onSubmit"]> = (event) => {
    event.preventDefault();

    if (editingMessage) {
      void sendEditedMessage();
      return;
    }

    void sendTextMessage();
  };

  const composerContextTitle = editingMessage
    ? "Editing message"
    : `Replying to ${replyingTo?.fromUserId === user.id ? "yourself" : (replyingTo?.fromUsername || selectedUser.username)}`;
  const composerContextPreview = editingMessage?.message ?? replyingTo?.replyPreview?.text ?? replyingTo?.message ?? "";
  const inputPlaceholder = uploadingImage
    ? "Uploading encrypted image..."
    : editingMessage
      ? "Edit your message"
      : "Type a message";

  let messageListContent: JSX.Element;
  if (loading) {
    messageListContent = (
      <div className="loading-state">
        <div className="loading-spinner"></div>
        <p>Loading messages...</p>
      </div>
    );
  } else if (messages.length === 0) {
    messageListContent = (
      <div className="empty-chat">
        <div className="empty-chat-icon">👋</div>
        <p>No messages yet. Say hello!</p>
      </div>
    );
  } else {
    messageListContent = (
      <>
        {messages.map((m, index) => {
          const previousMessage = index > 0 ? messages[index - 1] : null;
          const showDaySeparator =
            !previousMessage || getDayKey(previousMessage.createdAt) !== getDayKey(m.createdAt);
          const dayLabel = formatDayLabel(m.createdAt);

          return (
            <Fragment key={m.id}>
              {showDaySeparator && (
                <div className="message-day-separator">
                  <span>{dayLabel}</span>
                </div>
              )}
              <MessageBubble
                id={m.id}
                isOwn={m.fromUserId === user.id}
                message={m.message}
                contentType={m.contentType}
                imageUrl={m.imageUrl}
                imageFileName={m.imageFileName}
                replyPreview={m.replyPreview}
                isEdited={Boolean(m.editedAt)}
                timestamp={m.createdAt}
                username={m.fromUsername}
                formatTime={formatTime}
                status={m.status}
                actionsOpen={activeActionMessageId === m.id}
                canReply={!m.id.startsWith("temp-")}
                canEdit={isMessageEditable(m, user.id)}
                onToggleActions={() => {
                  setActiveActionMessageId((currentId) => currentId === m.id ? null : m.id);
                }}
                onReply={() => openReplyComposer(m)}
                onEdit={() => openEditComposer(m)}
              />
            </Fragment>
          );
        })}
      </>
    );
  }

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
            {statusLabel}
          </span>
        </div>
      </div>

      <div className="messages" ref={messageListRef}>
        {messageListContent}
        <div ref={messagesEndRef} />
      </div>

      <div className="composer-shell">
        {(replyingTo || editingMessage) && (
          <div className="composer-context-banner">
            <div className="composer-context-icon">
              {editingMessage ? <Pencil size={16} /> : <Reply size={16} />}
            </div>
            <div className="composer-context-copy">
              <strong>{composerContextTitle}</strong>
              <span>{composerContextPreview}</span>
            </div>
            <button
              type="button"
              className="composer-context-close"
              onClick={clearComposerContext}
              aria-label="Cancel composer context"
            >
              <X size={16} />
            </button>
          </div>
        )}

        <form className="input-area" onSubmit={handleComposerSubmit}>
          <button
            type="button"
            className="attach-btn"
            onClick={() => fileInputRef.current?.click()}
            disabled={loading || uploadingImage || !conversationKey || Boolean(editingMessage)}
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
            placeholder={inputPlaceholder}
            disabled={loading || uploadingImage}
            maxLength={1000}
            className="message-input"
            ref={inputRef}
          />
          <button
            type="submit"
            disabled={!input.trim() || loading || uploadingImage || !conversationKey}
            className="send-btn"
            aria-label={editingMessage ? "Save message edit" : "Send message"}
          >
            <Send size={20} />
          </button>
        </form>
      </div>
      {composerError && <div className="composer-error">{composerError}</div>}
    </div>
  );
};

export default ChatWindow;
