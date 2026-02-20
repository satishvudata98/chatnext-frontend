import { useState } from "react";
import type { FC, ChangeEvent } from "react";

interface User {
  id: string;
  username: string;
  email: string;
  online: boolean;
  last_seen?: number;
}

interface Props {
  users: User[];
  selectedUser: User | null;
  onSelect: (user: User) => void;
  loading?: boolean;
}

const UserList: FC<Props> = (props: Props): JSX.Element => {
  const {
    users,
    selectedUser,
    onSelect,
    loading = false
  } = props;
  const [searchQuery, setSearchQuery] = useState<string>("");

  const filteredUsers: User[] = users.filter((u: User): boolean =>
    u.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
    u.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <h2>Messages</h2>
      </div>

      <div className="search-box">
        <input
          type="text"
          placeholder="Search contacts..."
          value={searchQuery}
          onChange={(e: ChangeEvent<HTMLInputElement>): void => setSearchQuery(e.target.value)}
          className="search-input"
          disabled={loading}
        />
      </div>

      <div className="users-list">
        {loading ? (
          <div className="loading-state">Loading users...</div>
        ) : filteredUsers.length === 0 ? (
          <div className="no-users">
            {users.length === 0 ? "No users available" : "No results found"}
          </div>
        ) : (
          filteredUsers.map((u) => (
            <div
              key={u.id}
              className={`user ${u.id === selectedUser?.id ? "active" : ""}`}
              onClick={() => onSelect(u)}
            >
              <div className="user-avatar">{u.username.charAt(0).toUpperCase()}</div>
              <div className="user-info">
                <div className="user-name">{u.username}</div>
                <div className={`user-status ${u.online ? "online" : "offline"}`}>
                  {u.online ? "● Online" : "● Offline"}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default UserList;