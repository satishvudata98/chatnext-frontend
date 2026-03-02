import { useState, useEffect, useRef } from "react";
import type { FC, ChangeEvent } from "react";
import { Search, LogOut, Menu } from "lucide-react";

interface User {
  id: string;
  username: string;
  email: string;
  online?: boolean;
  last_seen?: number;
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
    unreadCounts = new Map()
  } = props;
  
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [showMenu, setShowMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  
  // Close menu when clicking outside
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
  
  const filteredUsers: User[] = users.filter(
    (u: User): boolean =>
      u.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.email.toLowerCase().includes(searchQuery.toLowerCase())
  );
  
  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="profile-section">
          <div className="profile-avatar">
            {currentUser.username.charAt(0).toUpperCase()}
          </div>
          <div className="profile-info">
            <h3>{currentUser.username}</h3>
            <span className={`status-badge status-${connectionStatus}`}>
              {connectionStatus === "connected" && "● Online"}
              {connectionStatus === "disconnected" && "● Offline"}
              {connectionStatus === "connecting" && "● Connecting..."}
              {connectionStatus === "reconnecting" && "● Reconnecting..."}
            </span>
          </div>
        </div>
        <div className="header-actions">
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
        <div className="search-box">
          <Search size={18} className="search-icon" />
          <input
            type="text"
            placeholder="Search or start new chat"
            value={searchQuery}
            onChange={(e: ChangeEvent<HTMLInputElement>): void =>
              setSearchQuery(e.target.value)
            }
            className="search-input"
            disabled={loading}
          />
        </div>
      </div>
      
      <div className="users-list">
        {loading ? (
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Loading contacts...</p>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="no-users">
            {users.length === 0
              ? "No contacts available"
              : "No results found"}
          </div>
        ) : (
          filteredUsers.map((u) => (
            <div
              key={u.id}
              className={`user-item ${u.id === selectedUser?.id ? "active" : ""}`}
              onClick={() => onSelect(u)}
            >
              <div className="user-avatar">
                {u.username.charAt(0).toUpperCase()}
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
