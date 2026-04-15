import { useState, useEffect, useRef } from "react";
import ThemeSwitcher from "./ThemeSwitcher";
import type { FC, ChangeEvent, FormEvent } from "react";
import { Search, LogOut, Menu } from "lucide-react";

interface User {
  id: string;
  username: string;
  email: string;
  online?: boolean;
  last_seen?: number;
  avatar_url?: string | null;
}

interface IncomingBuddyRequest {
  id: string;
  requester_id: string;
  receiver_id: string;
  status: string;
  created_at: number;
  requester: User;
}

interface Props {
  users: User[];
  selectedUser: User | null;
  onSelect: (user: User) => void;
  loading?: boolean;
  currentUser: User;
  connectionStatus: string;
  onLogout: () => void | Promise<void>;
  unreadCounts?: Map<string, number>;
  incomingBuddyRequests: IncomingBuddyRequest[];
  buddySearchResults: User[];
  searchingBuddies: boolean;
  onSearchBuddyUsers: (username: string) => Promise<void>;
  onSendBuddyRequest: (toUserId: string) => Promise<void>;
  onRespondBuddyRequest: (requestId: string, action: "accept" | "reject") => Promise<void>;
}

const UserList: FC<Props> = (props: Props): JSX.Element => {
  const {
    users,
    selectedUser,
    onSelect,
    loading = false,
    currentUser,
    connectionStatus,
    onLogout,
    unreadCounts = new Map(),
    incomingBuddyRequests,
    buddySearchResults,
    searchingBuddies,
    onSearchBuddyUsers,
    onSendBuddyRequest,
    onRespondBuddyRequest,
  } = props;

  const [searchQuery, setSearchQuery] = useState<string>("");
  const [showMenu, setShowMenu] = useState(false);
  const [actingRequestId, setActingRequestId] = useState<string | null>(null);
  const [sendingRequestUserId, setSendingRequestUserId] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const isSearchActive = searchQuery.trim().length > 0;

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowMenu(false);
      }
    };

    if (showMenu) {
      document.addEventListener("mousedown", handleClickOutside);
    }

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [showMenu]);

  const handleSearchSubmit = async (event?: FormEvent): Promise<void> => {
    if (event) event.preventDefault();
    const query = searchQuery.trim();
    if (!query) {
      await onSearchBuddyUsers("");
      return;
    }
    await onSearchBuddyUsers(query);
  };

  const handleSendBuddyRequest = async (toUserId: string): Promise<void> => {
    try {
      setSendingRequestUserId(toUserId);
      await onSendBuddyRequest(toUserId);
    } finally {
      setSendingRequestUserId(null);
    }
  };

  const handleRespond = async (requestId: string, action: "accept" | "reject"): Promise<void> => {
    try {
      setActingRequestId(requestId);
      await onRespondBuddyRequest(requestId, action);
    } finally {
      setActingRequestId(null);
    }
  };

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="profile-section">
          <div className="user-avatar">
            {typeof currentUser.avatar_url === "string" && currentUser.avatar_url.trim().length > 0 ? (
              <img
                src={currentUser.avatar_url}
                alt={currentUser.username}
                className="avatar-img"
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                  e.currentTarget.parentElement!.textContent =
                    currentUser.username.charAt(0).toUpperCase();
                }}
              />
            ) : (
              currentUser.username.charAt(0).toUpperCase()
            )}
          </div>
          <div className="profile-info">
            <h3>{currentUser.username}</h3>
            <span className={`status-badge status-${connectionStatus}`}>
              {connectionStatus === "connected" && "Online"}
              {connectionStatus === "disconnected" && "Offline"}
              {connectionStatus === "connecting" && "Connecting..."}
              {connectionStatus === "reconnecting" && "Reconnecting..."}
            </span>
          </div>
        </div>
        <div className="header-actions" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <ThemeSwitcher />
          <button
            className="menu-btn"
            onClick={() => setShowMenu(!showMenu)}
            aria-label="Menu"
          >
            <Menu size={20} />
          </button>
        </div>
        {showMenu && (
          <div className="dropdown-menu" ref={menuRef}>
            <button onClick={onLogout} className="menu-item logout-item">
              <LogOut size={18} />
              <span>Logout</span>
            </button>
          </div>
        )}
      </div>

      <div className="search-container">
        <form className="search-box" onSubmit={handleSearchSubmit}>
          <input
            type="text"
            placeholder="Search username to add buddy"
            value={searchQuery}
            onChange={(e: ChangeEvent<HTMLInputElement>): void =>
              setSearchQuery(e.target.value)
            }
            className="search-input"
            disabled={loading || searchingBuddies}
          />
          <button
            type="submit"
            className="search-submit-btn"
            aria-label="Search usernames"
            disabled={loading || searchingBuddies}
          >
            <Search size={18} className="search-icon" />
          </button>
        </form>
      </div>

      {incomingBuddyRequests.length > 0 && (
        <div className="buddy-request-section">
          <div className="section-title">Incoming Buddy Requests</div>
          {incomingBuddyRequests.map((request) => (
            <div className="buddy-request-item" key={request.id}>
              <div className="user-avatar">
                {request.requester.username.charAt(0).toUpperCase()}
              </div>
              <div className="user-info">
                <div className="user-name">{request.requester.username}</div>
                <div className="user-status">wants to be your buddy</div>
              </div>
              <div className="request-actions">
                <button
                  className="request-btn accept"
                  disabled={actingRequestId === request.id}
                  onClick={() => handleRespond(request.id, "accept")}
                >
                  Accept
                </button>
                <button
                  className="request-btn reject"
                  disabled={actingRequestId === request.id}
                  onClick={() => handleRespond(request.id, "reject")}
                >
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {isSearchActive && (
        <div className="buddy-search-results">
          <div className="section-title">Search Results</div>
          {searchingBuddies ? (
            <div className="no-users">Searching...</div>
          ) : buddySearchResults.length === 0 ? (
            <div className="no-users">No users available to add</div>
          ) : (
            buddySearchResults.map((candidate) => (
              <div className="buddy-search-item" key={candidate.id}>
                <div className="user-avatar">{candidate.username.charAt(0).toUpperCase()}</div>
                <div className="user-info">
                  <div className="user-name">{candidate.username}</div>
                  <div className={`user-status ${candidate.online ? "online" : "offline"}`}>
                    {candidate.online ? "online" : "offline"}
                  </div>
                </div>
                <button
                  className="add-buddy-btn"
                  disabled={sendingRequestUserId === candidate.id}
                  onClick={() => handleSendBuddyRequest(candidate.id)}
                >
                  {sendingRequestUserId === candidate.id ? "Sending..." : "Add Buddy"}
                </button>
              </div>
            ))
          )}
        </div>
      )}

      <div className={`users-list ${isSearchActive ? "hidden-by-search" : ""}`}>
        {loading ? (
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Loading buddies...</p>
          </div>
        ) : users.length === 0 ? (
          <div className="no-users">No buddies yet. Search to add one.</div>
        ) : (
          users.map((u) => (
            <div
              key={u.id}
              className={`user-item ${u.id === selectedUser?.id ? "active" : ""}`}
              onClick={() => onSelect(u)}
            >
              <div className="user-avatar">
                {typeof u.avatar_url === "string" && u.avatar_url.trim().length > 0 ? (
                  <img
                    src={u.avatar_url}
                    alt={u.username}
                    className="avatar-img"
                    onError={(e) => {
                      e.currentTarget.style.display = "none";
                      e.currentTarget.parentElement!.textContent =
                        u.username.charAt(0).toUpperCase();
                    }}
                  />
                ) : (
                  u.username.charAt(0).toUpperCase()
                )}
              </div>
              <div className="user-info">
                <div className="user-name">{u.username}</div>
                <div className={`user-status ${u.online ? "online" : "offline"}`}>
                  {u.online ? "online" : "offline"}
                </div>
              </div>
              {u.online && <div className="online-dot"></div>}
              {unreadCounts && unreadCounts.get(u.id) && unreadCounts.get(u.id)! > 0 && selectedUser?.id !== u.id && (
                <div className="unread-badge">{unreadCounts.get(u.id)}</div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default UserList;
