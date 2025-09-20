import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import https from 'https';
import { AuthService } from './services/AuthService.js';
import { MessageStore } from './services/MessageStore.js';
import { SocketHandler } from './handlers/SocketHandler.js';

const app = express();
const PORT = process.env.PORT || 3001;
const USE_HTTPS = process.env.USE_HTTPS === 'true';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Allow WebRTC
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-domain.com'] 
    : ['http://localhost:5173', 'https://localhost:5173'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.use(express.json({ limit: '5mb' }));

// Initialize services
const authService = new AuthService();
const messageStore = new MessageStore();

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    activeConnections: messageStore.getActiveConnections()
  });
});

// Session validation endpoint
app.post('/session', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }

  try {
    const decoded = authService.verifyToken(token);
    res.json({ valid: true, user: decoded.username });
  } catch (error) {
    res.status(401).json({ valid: false, error: 'Invalid token' });
  }
});

// Create server (HTTP or HTTPS)
let server;
if (USE_HTTPS && fs.existsSync('./certs/server.key') && fs.existsSync('./certs/server.crt')) {
  const options = {
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.crt')
  };
  server = https.createServer(options, app);
  console.log('🔒 HTTPS server enabled');
} else {
  server = createServer(app);
  if (USE_HTTPS) {
    console.log('⚠️  HTTPS requested but certificates not found. Run npm run gen-cert');
  }
}

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? ['https://your-domain.com'] 
      : ['http://localhost:5173', 'https://localhost:5173'],
    methods: ['GET', 'POST']
  }
});

// Initialize socket handler
new SocketHandler(io, authService, messageStore);

server.listen(PORT, () => {
  const protocol = USE_HTTPS ? 'https' : 'http';
  console.log(`🚀 Server running on ${protocol}://localhost:${PORT}`);
  console.log(`📱 Client should connect to: ${protocol}://localhost:5173`);
  console.log(`🔧 Server Version: IMMEDIATE-FIX-v1.0 - ${new Date().toISOString()}`);
});