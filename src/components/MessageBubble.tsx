import type { FC } from "react";

interface Props {
  isOwn: boolean;
  message: string;
  timestamp?: number;
  username?: string;
  formatTime?: (timestamp: number) => string;
}

function defaultFormatTime(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  const now = new Date();
  const isToday = date.toDateString() === now.toDateString();

  if (isToday) {
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false
    });
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric"
  });
}

const MessageBubble: FC<Props> = (props: Props): JSX.Element => {
  const {
    isOwn,
    message,
    timestamp = Math.floor(Date.now() / 1000),
    username,
    formatTime = defaultFormatTime
  } = props;
  return (
    <div className={`message-wrapper ${isOwn ? "sent-wrapper" : "received-wrapper"}`}>
      <div className={isOwn ? "sent" : "received"}>
        {!isOwn && username && <div className="message-username">{username}</div>}
        <div className="bubble">{message}</div>
        <span className="timestamp">{formatTime(timestamp)}</span>
      </div>
    </div>
  );
};

export default MessageBubble;