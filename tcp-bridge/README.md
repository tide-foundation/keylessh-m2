# KeyleSSH TCP Bridge

Stateless WebSocket-TCP bridge microservice for SSH connections. Designed to run on Azure Container Apps with auto-scaling.

## What it does

```
Browser (WebSocket) → TCP Bridge → SSH Server (TCP)
```

The bridge:
1. Accepts WebSocket connections with a signed session token
2. Opens TCP socket to the specified SSH server
3. Pipes bytes bidirectionally
4. Closes both connections when either side disconnects

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     Azure Container Apps                        │
│                                                                 │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐         │
│   │  Instance 1 │   │  Instance 2 │   │  Instance N │   ...   │
│   │  10 conns   │   │  10 conns   │   │  10 conns   │         │
│   └─────────────┘   └─────────────┘   └─────────────┘         │
│                                                                 │
│   Auto-scales 0 → 100 based on concurrent connections          │
└────────────────────────────────────────────────────────────────┘
```

## Security

- **Session tokens** are signed by the main server using HMAC-SHA256
- Tokens contain: `host`, `port`, `serverId`, `userId`, `exp`
- Tokens expire after 1 minute (only used for initial connection)
- The bridge trusts the main server's signature

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | HTTP/WebSocket port | No (default: 8080) |
| `BRIDGE_SECRET` | Shared secret with main server | Yes |

## Local Development

```bash
npm install
npm run dev
```

## Deploy to Azure

```bash
# Set the shared secret
export BRIDGE_SECRET=$(openssl rand -base64 32)

# Deploy
./azure/deploy.sh
```

## Health Check

```bash
curl http://localhost:8080/health
# {"status":"ok","connections":0}
```

## Protocol

### Connection

```
WebSocket URL: wss://bridge-host/?token=<session-token>
```

### Messages

**From bridge to client:**
```json
{"type": "connected"}  // TCP connection established
{"type": "error", "message": "..."}  // Error occurred
```

**Binary data** is forwarded as-is in both directions.
