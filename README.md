# KeyleSSH - Secure Web SSH Console

A secure, multi-user web-based SSH console with OIDC authentication. SSH encryption happens entirely in the browser - private keys never leave the client.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  BROWSER                                     │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐ │
│  │   TideCloak     │  │    xterm.js      │  │  @microsoft/dev-tunnels-ssh │ │
│  │   React SDK     │  │    Terminal      │  │  (SSH Protocol Handler)     │ │
│  │                 │  │                  │  │                             │ │
│  │  - OIDC Login   │  │  - Display       │  │  - Key Import (in-memory)   │ │
│  │  - JWT Tokens   │  │  - Input/Output  │  │  - SSH Handshake            │ │
│  │  - Auto Refresh │  │  - Resize        │  │  - Encryption/Decryption    │ │
│  └────────┬────────┘  └────────┬─────────┘  └──────────────┬──────────────┘ │
│           │                    │                           │                 │
│           │              User Input/Output          Encrypted SSH Data       │
│           │                    │                           │                 │
│           ▼                    ▼                           ▼                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                         WebSocket Connection                             │ │
│  │                    wss://host/ws/tcp?host=X&port=Y                       │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│   🔒 Private Key NEVER leaves here   │   (Only encrypted SSH traffic)        │
└──────────────────────────────────────┼───────────────────────────────────────┘
                                       │
                                       │ TLS Encrypted
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXPRESS SERVER                                  │
│                                                                              │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐ │
│  │   REST API      │  │  JWT Middleware  │  │   WebSocket-TCP Bridge      │ │
│  │                 │  │                  │  │                             │ │
│  │  /api/servers   │  │  - Decode Token  │  │  - Validate JWT             │ │
│  │  /api/sessions  │  │  - Check Expiry  │  │  - Check Server Access      │ │
│  │  /api/admin/*   │  │  - Extract User  │  │  - Create TCP Socket        │ │
│  │                 │  │  - Check Roles   │  │  - Bidirectional Pipe       │ │
│  └────────┬────────┘  └────────┬─────────┘  └──────────────┬──────────────┘ │
│           │                    │                           │                 │
│           ▼                    │                           ▼                 │
│  ┌─────────────────┐           │            ┌─────────────────────────────┐ │
│  │  Storage        │           │            │   TCP Socket                │ │
│  │  (SQLite)       │           │            │   Raw Bytes ←→ SSH Server   │ │
│  │                 │           │            └──────────────┬──────────────┘ │
│  │  - Servers      │           │                           │                 │
│  │  - Sessions     │           │                           │                 │
│  └─────────────────┘           │                           │                 │
│                                │                           │                 │
└────────────────────────────────┼───────────────────────────┼─────────────────┘
                                 │                           │
                    ┌────────────┘                           │
                    │                                        │
                    ▼                                        ▼
┌─────────────────────────────────┐      ┌─────────────────────────────────────┐
│         TIDECLOAK               │      │           SSH SERVER                │
│     (Keycloak-based IdP)        │      │                                     │
│                                 │      │   - Receives encrypted SSH traffic  │
│  - User Authentication          │      │   - Authenticates with public key   │
│  - JWT Token Issuance           │      │   - Opens shell session             │
│  - Role Management              │      │   - Sends/receives data             │
│  - User Claims + Roles          │      │                                     │
│    (OIDC + client roles)        │      │   Example: 192.168.1.100:22         │
│                                 │      │                                     │
└─────────────────────────────────┘      └─────────────────────────────────────┘
```

## Security Model

### Private Key Security
- **Private keys are imported in the browser** using Web Crypto API
- **Keys never leave the browser** - all SSH encryption happens client-side
- **Backend is a dumb pipe** - only forwards encrypted bytes, cannot decrypt
- **Optional session storage** - keys can be remembered for tab lifetime only

### Authentication Flow
```
┌──────────┐     ┌──────────────┐     ┌───────────┐     ┌─────────────┐
│  User    │────▶│  TideCloak   │────▶│  Backend  │────▶│ SSH Server  │
└──────────┘     └──────────────┘     └───────────┘     └─────────────┘
     │                  │                   │                  │
     │  1. Login        │                   │                  │
     │─────────────────▶│                   │                  │
     │                  │                   │                  │
     │  2. JWT Token    │                   │                  │
     │◀─────────────────│                   │                  │
     │  (includes roles)                    │                  │
     │                  │                   │                  │
     │  3. API Request + Bearer Token       │                  │
     │─────────────────────────────────────▶│                  │
     │                  │                   │                  │
     │                  │  4. Validate JWT  │                  │
     │                  │     Check Access  │                  │
     │                  │                   │                  │
     │  5. WebSocket + Token                │                  │
     │─────────────────────────────────────▶│                  │
     │                  │                   │                  │
     │                  │                   │  6. TCP Connect  │
     │                  │                   │─────────────────▶│
     │                  │                   │                  │
     │  7. SSH Handshake (encrypted, browser handles crypto)   │
     │◀───────────────────────────────────────────────────────▶│
     │                  │                   │                  │
     │  8. Interactive Shell Session        │                  │
     │◀═══════════════════════════════════════════════════════▶│
```

### Role-Based Access Control
| Role | Permissions |
|------|-------------|
| `user` | View enabled servers and start SSH sessions |
| `admin` | Access all servers, manage users, manage servers |

Admin role is determined by the `tide-realm-admin` client role under `realm-management` in TideCloak.

## Tech Stack

### Frontend
- **React 18** + TypeScript
- **Vite** - Build tool
- **TailwindCSS** - Styling (dark theme)
- **Shadcn/ui** - UI components
- **xterm.js** - Terminal emulator
- **@microsoft/dev-tunnels-ssh** - Browser SSH client
- **@tidecloak/react** - OIDC authentication
- **TanStack Query** - Server state management
- **Wouter** - Routing

### Backend
- **Express.js** - HTTP server
- **ws** - WebSocket server
- **JWT** - Token verification via TideCloak JWKS

## Project Structure

```
├── client/
│   └── src/
│       ├── components/
│       │   ├── layout/           # App layout, sidebar
│       │   ├── ui/               # Shadcn UI components
│       │   └── PrivateKeyInput.tsx
│       ├── contexts/
│       │   └── AuthContext.tsx   # TideCloak auth wrapper
│       ├── hooks/
│       │   └── useSSHSession.ts  # SSH connection hook
│       ├── lib/
│       │   ├── api.ts            # API client
│       │   ├── queryClient.ts    # TanStack Query setup
│       │   └── sshClient.ts      # Browser SSH client
│       ├── pages/
│       │   ├── Login.tsx
│       │   ├── Dashboard.tsx
│       │   ├── Console.tsx       # SSH terminal page
│       │   ├── AdminDashboard.tsx
│       │   ├── AdminServers.tsx
│       │   ├── AdminUsers.tsx
│       │   ├── AdminRoles.tsx
│       │   ├── AdminApprovals.tsx
│       │   ├── AdminSessions.tsx
│       │   └── AdminLogs.tsx
│       └── tidecloakAdapter.json # TideCloak configuration
├── server/
│   ├── index.ts                  # Express app setup
│   ├── routes.ts                 # API endpoints
│   ├── auth.ts                   # JWT middleware + Keycloak Admin API
│   ├── wsBridge.ts               # WebSocket-TCP bridge
│   └── storage.ts                # SQLite data store
└── shared/
    └── schema.ts                 # Shared TypeScript types
```

## API Endpoints

### User Endpoints (Authenticated)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/servers` | List enabled servers |
| GET | `/api/servers/:id` | Get server details |
| GET | `/api/sessions` | List user's sessions (active + completed) |
| POST | `/api/sessions` | Create new session record |
| DELETE | `/api/sessions/:id` | End session |
| POST | `/api/ssh/authorize` | Authorize SSH connection |

### Admin Endpoints (Admin Role Required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/servers` | List all servers |
| POST | `/api/admin/servers` | Create server |
| PATCH | `/api/admin/servers/:id` | Update server |
| DELETE | `/api/admin/servers/:id` | Delete server |
| GET | `/api/admin/users` | List all users (from TideCloak) |
| POST | `/api/admin/users` | Update user roles |
| PUT | `/api/admin/users` | Update user profile |
| DELETE | `/api/admin/users` | Delete user |
| POST | `/api/admin/users/add` | Create user |
| GET | `/api/admin/sessions` | List all sessions (active + completed) |
| POST | `/api/admin/sessions/:id/terminate` | Terminate an active session |
| GET | `/api/admin/logs/access` | TideCloak user events for this client |
| GET | `/api/admin/roles` | List client roles |
| GET | `/api/admin/roles/all` | List all roles |
| POST | `/api/admin/approvals` | Create approval / cast decision |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `ws://host/ws/tcp?host=X&port=Y&serverId=Z&sessionId=S&token=T` | TCP bridge for SSH (requires a pre-created session record) |

## Environment Variables

```env
# Server
PORT=3000                                    # Server port

# TideCloak/Keycloak (optional, defaults provided)
KEYCLOAK_URL=https://staging.dauth.me        # TideCloak server URL
KEYCLOAK_REALM=keylessh                      # Realm name
```

## Running the Application

### Development
```bash
npm install
npm run dev
```

### Production Build
```bash
npm run build
npm start
```

### Type Checking
```bash
npm run check
```

## Local Testing

### Testing Everything Together (Default Mode)

By default, the main server handles TCP bridging locally. This is the simplest setup for development:

```bash
# Terminal 1: Start the main server
npm run dev

# The app runs at http://localhost:3000
# WebSocket bridge is at ws://localhost:3000/ws/tcp
```

Then:
1. Open http://localhost:3000 in your browser
2. Login with TideCloak
3. Navigate to a server console
4. Enter your SSH private key
5. Connect to the SSH server

### Testing TCP Bridge Separately

To test the TCP bridge microservice independently (simulates production architecture):

```bash
# Terminal 1: Start the TCP bridge
cd tcp-bridge
npm install
BRIDGE_SECRET=test-secret npm run dev
# Runs on http://localhost:8080

# Terminal 2: Start the main server with external bridge
BRIDGE_URL=ws://localhost:8080 BRIDGE_SECRET=test-secret npm run dev
# Runs on http://localhost:3000
```

This setup mimics production where:
- Main server handles authentication and creates signed session tokens
- TCP bridge receives tokens and manages SSH connections

### Testing SSH Connection Manually

You can test the WebSocket-TCP bridge directly using `wscat`:

```bash
# Install wscat
npm install -g wscat

# Connect to bridge (local mode, requires valid JWT + a valid sessionId created via POST /api/sessions)
wscat -c "ws://localhost:3000/ws/tcp?host=your-ssh-server.com&port=22&serverId=server-id&sessionId=session-id&token=YOUR_JWT_TOKEN"
```

### Health Check

```bash
# Check main server
curl http://localhost:3000/api/health

# Check TCP bridge (when running separately)
curl http://localhost:8080/health
# Returns: {"status":"ok","connections":0}
```

## SSH Connection Flow

1. **User navigates to** `/app/console/:serverId?user=username`
2. **Frontend fetches** server details from API
3. **Private key dialog** appears - user pastes/uploads their SSH private key
4. **Frontend creates a session record** via `POST /api/sessions` (serverId + sshUser)
5. **Frontend opens WebSocket** to `/ws/tcp` including the returned `sessionId`
6. **Backend verifies JWT** and validates the `sessionId` belongs to the token user + serverId
   - The bridge also enforces that `host:port` matches the configured server record
7. **Backend opens TCP socket** to SSH server (e.g., 192.168.1.100:22)
8. **Browser's SSH library** performs handshake over WebSocket
   - Key exchange, authentication all happen in browser
   - Backend just forwards encrypted bytes
9. **Shell channel opened**, bound to xterm.js terminal
10. **User interacts** with remote shell

## TideCloak Configuration

The TideCloak adapter configuration is in `client/src/tidecloakAdapter.json`:

```json
{
  "realm": "keylessh",
  "authServerUrl": "https://staging.dauth.me",
  "resource": "keylessh",
  ...
}
```

### Required TideCloak Setup
1. Create a realm (e.g., `keylessh`)
2. Create a client (e.g., `keylessh`) with:
   - Client authentication: OFF (public client)
   - Valid redirect URIs: Your app URLs
3. For admin users, assign the `tide-realm-admin` role from the `realm-management` client
4. To allow admins to manage users via API, also assign `view-users` and `manage-users` roles

### User Attributes
This app relies on standard OIDC claims (sub/username/email) and TideCloak roles for authorization.

## Scalable Deployment with Azure Container Apps

For production deployments with many concurrent SSH sessions, the TCP bridge can be deployed as a separate, auto-scaling microservice.

### Architecture

```
┌────────┐    ┌─────────────────┐    ┌─────────────────────┐    ┌──────────┐
│Browser │───▶│  Main Server    │───▶│ Azure Container App │───▶│SSH Server│
│   WS   │    │  (JWT + Auth)   │    │   (TCP Bridge)      │    │          │
└────────┘    └─────────────────┘    │   Scales 0 → 100    │    └──────────┘
                                     └─────────────────────┘
```

- **Main Server**: Handles JWT validation, API, creates signed session tokens
- **TCP Bridge**: Stateless container that pipes WebSocket ↔ TCP
- **Auto-scaling**: 0 instances when idle, scales based on concurrent connections

### Deploy TCP Bridge to Azure

```bash
cd tcp-bridge

# Set your bridge secret (used to sign session tokens)
export BRIDGE_SECRET=$(openssl rand -base64 32)

# Deploy to Azure Container Apps
./azure/deploy.sh
```

### Configure Main Server

After deployment, add these environment variables to your main server:

```env
BRIDGE_URL=wss://keylessh-tcp-bridge.<region>.azurecontainerapps.io
BRIDGE_SECRET=<same-secret-from-deployment>
```

### Scaling Configuration

The bridge auto-scales based on concurrent connections:
- **Min replicas**: 0 (scales to zero when no connections)
- **Max replicas**: 100 (adjust in `azure/container-app.yaml`)
- **Connections per instance**: 10 (each SSH session = 1 connection)

This means:
- 0 users = 0 instances (no cost)
- 50 users = 5 instances
- 500 users = 50 instances

### Local Development

By default (no `BRIDGE_URL` set), the server handles TCP bridging locally. This is fine for development and small deployments.

## License

MIT
