export type MessageContentType = "text" | "image";

export interface ImageMessagePayload {
  type: "image";
  mediaId: string;
  mediaKey: string;
  mediaIv: string;
  mimeType: string;
  fileName?: string;
}

export interface ReplyPreviewPayload {
  messageId: string;
  fromUserId: string;
  fromUsername: string;
  contentType: MessageContentType;
  text: string;
}

interface StructuredTextMessagePayload {
  version: 1;
  contentType: "text";
  text: string;
  reply: ReplyPreviewPayload | null;
}

interface StructuredImageMessagePayload {
  version: 1;
  contentType: "image";
  image: ImageMessagePayload;
  reply: ReplyPreviewPayload | null;
}

type StructuredMessagePayload = StructuredTextMessagePayload | StructuredImageMessagePayload;

export type ParsedDecryptedMessagePayload =
  | {
      contentType: "text";
      text: string;
      replyPreview: ReplyPreviewPayload | null;
    }
  | {
      contentType: "image";
      text: string;
      imagePayload: ImageMessagePayload;
      replyPreview: ReplyPreviewPayload | null;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object";
}

function isImageMessagePayload(value: unknown): value is ImageMessagePayload {
  return (
    isRecord(value) &&
    value.type === "image" &&
    typeof value.mediaId === "string" &&
    typeof value.mediaKey === "string" &&
    typeof value.mediaIv === "string" &&
    typeof value.mimeType === "string"
  );
}

function isReplyPreviewPayload(value: unknown): value is ReplyPreviewPayload {
  return (
    isRecord(value) &&
    typeof value.messageId === "string" &&
    typeof value.fromUserId === "string" &&
    typeof value.fromUsername === "string" &&
    (value.contentType === "text" || value.contentType === "image") &&
    typeof value.text === "string"
  );
}

export function parseDecryptedMessagePayload(rawMessage: string): ParsedDecryptedMessagePayload {
  try {
    const parsed = JSON.parse(rawMessage) as unknown;

    if (isRecord(parsed) && parsed.version === 1 && parsed.contentType === "text") {
      return {
        contentType: "text",
        text: typeof parsed.text === "string" ? parsed.text : "",
        replyPreview: isReplyPreviewPayload(parsed.reply) ? parsed.reply : null,
      };
    }

    if (isRecord(parsed) && parsed.version === 1 && parsed.contentType === "image" && isImageMessagePayload(parsed.image)) {
      return {
        contentType: "image",
        text: "[Image]",
        imagePayload: parsed.image,
        replyPreview: isReplyPreviewPayload(parsed.reply) ? parsed.reply : null,
      };
    }

    if (isImageMessagePayload(parsed)) {
      return {
        contentType: "image",
        text: "[Image]",
        imagePayload: parsed,
        replyPreview: null,
      };
    }
  } catch {
    // Keep backward compatibility with legacy plaintext messages.
  }

  return {
    contentType: "text",
    text: rawMessage,
    replyPreview: null,
  };
}

export function buildTextMessagePayload(
  text: string,
  replyPreview: ReplyPreviewPayload | null,
): string {
  const payload: StructuredMessagePayload = {
    version: 1,
    contentType: "text",
    text,
    reply: replyPreview,
  };

  return JSON.stringify(payload);
}

export function buildImageMessagePayload(
  imagePayload: ImageMessagePayload,
  replyPreview: ReplyPreviewPayload | null,
): string {
  const payload: StructuredMessagePayload = {
    version: 1,
    contentType: "image",
    image: imagePayload,
    reply: replyPreview,
  };

  return JSON.stringify(payload);
}

export function buildReplyPreviewPayload(message: {
  id: string;
  fromUserId: string;
  fromUsername: string;
  message: string;
  contentType: MessageContentType;
  imageFileName?: string;
}): ReplyPreviewPayload {
  const previewText = message.contentType === "image"
    ? (message.imageFileName ? `[Image] ${message.imageFileName}` : "[Image]")
    : message.message;

  return {
    messageId: message.id,
    fromUserId: message.fromUserId,
    fromUsername: message.fromUsername,
    contentType: message.contentType,
    text: previewText,
  };
}