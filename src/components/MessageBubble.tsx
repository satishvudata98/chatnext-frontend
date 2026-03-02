import type { FC } from "react";

interface Props {
  isOwn: boolean;
  message: string;
  contentType?: "text" | "image";
  imageUrl?: string;
  imageFileName?: string;
  timestamp?: number;
  username?: string;
  formatTime?: (timestamp: number) => string;
  status?: string;
}

function defaultFormatTime(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  const now = new Date();
  const isToday = date.toDateString() === now.toDateString();

  if (isToday) {
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

const MessageBubble: FC<Props> = (props: Props): JSX.Element => {
  const {
    isOwn,
    message,
    contentType = "text",
    imageUrl,
    imageFileName,
    timestamp = Math.floor(Date.now() / 1000),
    username,
    formatTime = defaultFormatTime,
    status = "sent",
  } = props;

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

  return (
    <div className={`message-wrapper ${isOwn ? "sent-wrapper" : "received-wrapper"}`}>
      <div className={isOwn ? "sent" : "received"}>
        {!isOwn && username && <div className="message-username">{username}</div>}
        <div className={`bubble ${contentType === "image" ? "bubble-image" : ""}`}>
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
        </div>
        <span className={`timestamp ${getStatusClass()}`}>
          {formatTime(timestamp)}
          {isOwn && <span className={`status-tick ${getStatusClass()}`}>{getStatusIcon()}</span>}
        </span>
      </div>
    </div>
  );
};

export default MessageBubble;
