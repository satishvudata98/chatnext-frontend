# Chat Frontend

A modern real-time chat application built with React and TypeScript. This frontend connects to a backend API to provide instant messaging capabilities with user authentication and conversation management.

## Authentication

The app uses a secure token-based authentication system with access and refresh tokens:

- **Access Token**: Short-lived (15 minutes), stored in localStorage
- **Refresh Token**: Long-lived (7 days), stored securely in database
- **Automatic Refresh**: Tokens are refreshed automatically when expired
- **Secure Logout**: All tokens cleared on logout

## End-to-End Encryption

ChatNext features **military-grade end-to-end encryption (E2EE)** to protect your messages:

- **Zero-Knowledge Architecture**: Server cannot read your messages
- **Perfect Forward Secrecy**: Each conversation uses unique encryption keys
- **AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **ECDH Key Exchange**: Secure key establishment between users
- **Client-Side Crypto**: All encryption happens in your browser

### How E2EE Works

1. **Key Generation**: Each user gets a unique cryptographic key pair
2. **Key Exchange**: Public keys are shared to establish secure connections
3. **Message Encryption**: Messages are encrypted before leaving your device
4. **Secure Transmission**: Only encrypted data travels through the network
5. **Local Decryption**: Messages are decrypted only on recipient devices

Your privacy is protected even if the server is compromised.

## Navigation

- If user has valid tokens, app automatically navigates to `/chat`
- Invalid/expired tokens redirect to home page
- Protected routes require authentication

## Tech Stack

- **React 19** - UI framework
- **TypeScript** - Type-safe development
- **Vite** - Fast build tool and dev server
- **React Router** - Client-side routing
- **ESLint** - Code quality and linting

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Configure the API endpoint in `src/config/config.ts` to point to your backend server.

## Development

Start the development server:
```bash
npm run dev
```

The application will be available at `http://localhost:5173` (or the port shown in your terminal).

## Build

Build for production:
```bash
npm run build
```

The optimized build will be in the `dist/` directory.

## Preview

Preview the production build locally:
```bash
npm run preview
```

## Linting

Run ESLint to check code quality:
```bash
npm lint
```

## Project Structure

```
src/
├── api/              # API integration and requests
├── components/       # Reusable React components
│   ├── ChatWindow    # Main chat interface
│   ├── MessageBubble # Individual message display
│   └── UserList      # User listing component
├── config/           # Configuration files
├── pages/            # Page components (routing)
│   ├── Home
│   ├── Login
│   ├── Register
│   └── Chat
├── styles/           # CSS stylesheets
├── App.tsx           # Main app component
└── main.tsx          # Entry point
```

## Getting Started

1. **Register**: Create a new account via the Register page
2. **Login**: Log in with your credentials
3. **Chat**: Select a user from the list and start messaging

## Environment Variables

Configure your API endpoint in `src/config/config.ts` before deployment.

## License

MIT
