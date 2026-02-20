# Chat Frontend

A modern real-time chat application built with React and TypeScript. This frontend connects to a backend API to provide instant messaging capabilities with user authentication and conversation management.

## Features

- **User Authentication**: Register new accounts and log in securely
- **Real-time Messaging**: Send and receive messages instantly
- **User List**: View all available users with online/offline status
- **Conversation Management**: Start conversations with any user
- **Responsive UI**: Clean and intuitive user interface

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
