import { useEffect, useRef } from "react";
import type { ComponentPropsWithoutRef, FC } from "react";
import { MoreHorizontal, Pencil, Reply } from "lucide-react";
import type { ReplyPreviewPayload } from "../utils/messagePayload";

interface Props {
  id: string;
  isOwn: boolean;
  message: string;
  contentType?: "text" | "image";
  imageUrl?: string;
  imageFileName?: string;
  replyPreview?: ReplyPreviewPayload | null;
  isEdited?: boolean;
  timestamp?: number;
  username?: string;
  formatTime?: (timestamp: number) => string;
  status?: string;
  actionsOpen?: boolean;
  canReply?: boolean;
  canEdit?: boolean;
  onToggleActions?: () => void;
  onReply?: () => void;
  onEdit?: () => void;
}

const LONG_PRESS_DELAY_MS = 450;

function defaultFormatTime(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

const MessageBubble: FC<Props> = (props: Props): JSX.Element => {
  const {
    id,
    isOwn,
    message,
    contentType = "text",
    imageUrl,
    imageFileName,
    replyPreview = null,
    isEdited = false,
    timestamp = Math.floor(Date.now() / 1000),
    username,
    formatTime = defaultFormatTime,
    status = "sent",
    actionsOpen = false,
    canReply = false,
    canEdit = false,
    onToggleActions,
    onReply,
    onEdit,
  } = props;
  const longPressTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (longPressTimerRef.current !== null) {
        window.clearTimeout(longPressTimerRef.current);
      }
    };
  }, []);

  const clearLongPress = (): void => {
    if (longPressTimerRef.current !== null) {
      window.clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
  };

  const handlePointerDown: NonNullable<ComponentPropsWithoutRef<"div">["onPointerDown"]> = (event) => {
    if (!onToggleActions || event.pointerType !== "touch") return;

    clearLongPress();
    longPressTimerRef.current = window.setTimeout(() => {
      onToggleActions();
      longPressTimerRef.current = null;
    }, LONG_PRESS_DELAY_MS);
  };

  const hasActions = canReply || canEdit;

  const getStatusIcon = (): string => {
    if (!isOwn) return "";
    switch (status) {
      case "seen":
        return "✓✓";
      case "delivered":
        return "✓✓";
      case "sent":
        return "✓";
      default:
        return "✓";
    }
  };

  const getStatusClass = (): string => {
    if (!isOwn) return "";
    return `status-${status || "sent"}`;
  };

  const actions = hasActions ? (
    <div className="message-actions">
      <button
        type="button"
        className={`message-actions-trigger ${actionsOpen ? "open" : ""}`}
        onClick={onToggleActions}
        aria-label={`Open message actions for ${id}`}
      >
        <MoreHorizontal size={16} />
      </button>
      {actionsOpen && (
        <div className="message-actions-menu" role="menu">
          {canReply && (
            <button type="button" className="message-actions-item" onClick={onReply} role="menuitem">
              <Reply size={14} />
              <span>Reply</span>
            </button>
          )}
          {canEdit && (
            <button type="button" className="message-actions-item" onClick={onEdit} role="menuitem">
              <Pencil size={14} />
              <span>Edit</span>
            </button>
          )}
        </div>
      )}
    </div>
  ) : null;

  return (
    <div className={`message-wrapper ${isOwn ? "sent-wrapper" : "received-wrapper"}`}>
      <div className={isOwn ? "sent" : "received"}>
        {!isOwn && username && <div className="message-username">{username}</div>}
        <div className={`bubble-row ${isOwn ? "bubble-row-own" : "bubble-row-other"}`}>
          {!isOwn && actions}
          <div
            className={`bubble ${contentType === "image" ? "bubble-image" : ""}`}
            onPointerDown={handlePointerDown}
            onPointerUp={clearLongPress}
            onPointerCancel={clearLongPress}
            onPointerLeave={clearLongPress}
          >
            {replyPreview && (
              <div className={`reply-preview ${isOwn ? "reply-preview-own" : "reply-preview-other"}`}>
                <div className="reply-preview-author">{replyPreview.fromUsername}</div>
                <div className="reply-preview-text">{replyPreview.text}</div>
              </div>
            )}
            {contentType === "image" && imageUrl ? (
              <>
                <img
                  src={imageUrl}
                  alt={imageFileName || "Shared image"}
                  className="message-image"
                  loading="lazy"
                />
                {imageFileName && <div className="message-file-name">{imageFileName}</div>}
              </>
            ) : (
              <div className="bubble-text">{message}</div>
            )}
            <span className={`timestamp ${getStatusClass()}`}>
              {isEdited && <span className="edited-indicator">edited</span>}
              {formatTime(timestamp)}
              {isOwn && <span className={`status-tick ${getStatusClass()}`}>{getStatusIcon()}</span>}
            </span>
          </div>
          {isOwn && actions}
        </div>
      </div>
    </div>
  );
};

export default MessageBubble;
