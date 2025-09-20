import { Server, Socket } from 'socket.io';
import { AuthService } from '../services/AuthService.js';
import { MessageStore, Message } from '../services/MessageStore.js';

interface LogContext {
  socketId: string;
  userId?: string;
  timestamp: string;
  [key: string]: any;
}

export class SocketHandler {
  private connectedUsers = new Map<string, string>(); // socketId -> username
  private onlineUsers = new Set<string>(); // Set of online usernames
  private static readonly COMPONENT = 'SocketHandler';
  private static readonly VERSION = 'v2.0-join-fix'; // Version identifier
  private cleanupInterval!: NodeJS.Timeout;

  constructor(
    private io: Server,
    private authService: AuthService,
    private messageStore: MessageStore
  ) {
    console.log(`🚀 [SOCKET-HANDLER] Initializing SocketHandler ${SocketHandler.VERSION}`);
    this.setupSocketHandlers();
    this.startCleanupInterval();
  }

  private startCleanupInterval(): void {
    // Check for expired disappearing photos every 5 seconds
    this.cleanupInterval = setInterval(() => {
      const expiredIds = this.messageStore.getExpiredDisappearingPhotos();
      expiredIds.forEach(messageId => {
        this.messageStore.removeDisappearingPhoto(messageId);
        this.io.to('chat-room').emit('message-removed', { messageId });
      });
    }, 5000);
  }

  private log(level: 'info' | 'warn' | 'error', message: string, context: LogContext): void {
    const logEntry = {
      level: level.toUpperCase(),
      component: SocketHandler.COMPONENT,
      message,
      ...context
    };

    const logMessage = `[${logEntry.level}] ${logEntry.timestamp} [${logEntry.component}] ${message}`;
    
    switch (level) {
      case 'info':
        console.log(logMessage, context);
        break;
      case 'warn':
        console.warn(logMessage, context);
        break;
      case 'error':
        console.error(logMessage, context);
        break;
    }
  }

  private setupSocketHandlers(): void {
    this.io.on('connection', (socket: Socket) => {
      this.log('info', `Client connected`, {
        socketId: socket.id,
        timestamp: new Date().toISOString(),
        clientIP: socket.handshake.address,
        userAgent: socket.handshake.headers['user-agent']
      });

      // Authentication required for all events
      socket.on('login', (data) => this.handleLogin(socket, data));
      
      // Protected events (require authentication)
      socket.on('join', () => this.handleJoin(socket));
      socket.on('message', (data) => this.handleMessage(socket, data));
      socket.on('seen-once-viewed', (data) => this.handleSeenOnceViewed(socket, data));
      socket.on('photo-viewed', (data) => this.handlePhotoViewed(socket, data));
      socket.on('message-reaction', (data) => this.handleMessageReaction(socket, data));
      socket.on('typing', (data) => this.handleTyping(socket, data));
      
      // WebRTC signaling events
      socket.on('offer', (data) => this.handleOffer(socket, data));
      socket.on('answer', (data) => this.handleAnswer(socket, data));
      socket.on('ice-candidate', (data) => this.handleIceCandidate(socket, data));
      socket.on('call-start', (data) => this.handleCallStart(socket, data));
      socket.on('call-end', () => this.handleCallEnd(socket));
      socket.on('video-state-change', (data) => this.handleVideoStateChange(socket, data));
      socket.on('hold-state-change', (data) => this.handleHoldStateChange(socket, data));

      socket.on('disconnect', () => this.handleDisconnect(socket));
    });
  }

  private handleLogin(socket: Socket, data: { secretKey: string }): void {
    const startTime = Date.now();
    console.log(`🔍 [SOCKET-LOGIN] Raw data received:`, JSON.stringify(data, null, 2));
    console.log(`🔍 [SOCKET-LOGIN] Data type: ${typeof data}, Keys: ${Object.keys(data)}`);
    
    try {
      const { secretKey } = data;
      console.log(`🔍 [SOCKET-LOGIN] Extracted secretKey: "${secretKey}" (type: ${typeof secretKey})`);
      
      this.log('info', `Login attempt`, {
        socketId: socket.id,
        timestamp: new Date().toISOString(),
        secretKeyLength: secretKey?.length || 0,
        secretKeyValue: secretKey
      });
      
      // Add explicit validation check with detailed logging
      console.log(`🔍 [SOCKET-LOGIN] About to validate secret key: "${secretKey}"`);
      const isValidKey = this.authService.validateSecretKey(secretKey);
      console.log(`🔍 [SOCKET-LOGIN] Validation result: ${isValidKey}`);
      
      if (!isValidKey) {
        const duration = Date.now() - startTime;
        console.log(`❌ [SOCKET-LOGIN] VALIDATION FAILED for "${secretKey}"`);
        this.log('warn', `Invalid secret key provided`, {
          socketId: socket.id,
          timestamp: new Date().toISOString(),
          secretKeyLength: secretKey?.length || 0,
          secretKeyValue: secretKey,
          duration: `${duration}ms`
        });
        socket.emit('login-error', { error: 'Invalid credentials' });
        return;
      }

      console.log(`✅ [SOCKET-LOGIN] VALIDATION PASSED for "${secretKey}"`);
      const username = this.authService.getUsername(secretKey);
      console.log(`🔍 [SOCKET-LOGIN] Username mapping: "${secretKey}" -> "${username}"`);
      
      this.log('info', `Username mapped successfully`, {
        socketId: socket.id,
        timestamp: new Date().toISOString(),
        userId: username,
        secretKeyLength: secretKey.length,
        secretKeyValue: secretKey
      });
      
      // Check if user is already connected
      const hasConnection = this.messageStore.hasConnection(username);
      console.log(`🔍 [SOCKET-LOGIN] User "${username}" already connected: ${hasConnection}`);
      
      if (hasConnection) {
        const duration = Date.now() - startTime;
        console.log(`❌ [SOCKET-LOGIN] User "${username}" already connected`);
        this.log('warn', `User already connected`, {
          socketId: socket.id,
          timestamp: new Date().toISOString(),
          userId: username,
          duration: `${duration}ms`
        });
        socket.emit('login-error', { error: 'Invalid credentials' });
        return;
      }

      // Check connection limit (max 2 users)
      const connectionCount = this.messageStore.getConnectionCount();
      console.log(`🔍 [SOCKET-LOGIN] Current connections: ${connectionCount}/2`);
      
      if (connectionCount >= 2) {
        const duration = Date.now() - startTime;
        console.log(`❌ [SOCKET-LOGIN] Room is full (${connectionCount}/2)`);
        this.log('warn', `Room is full`, {
          socketId: socket.id,
          timestamp: new Date().toISOString(),
          userId: username,
          currentConnections: connectionCount,
          duration: `${duration}ms`
        });
        socket.emit('login-error', { error: 'Room is full' });
        return;
      }

      console.log(`🔍 [SOCKET-LOGIN] Generating token for "${secretKey}"`);
      const token = this.authService.generateToken(secretKey);
      console.log(`🔍 [SOCKET-LOGIN] Token generated (length: ${token.length})`);
      
      this.connectedUsers.set(socket.id, username);
      this.onlineUsers.add(username);
      this.messageStore.addConnection(username);

      console.log(`✅ [SOCKET-LOGIN] SUCCESS: User "${username}" logged in with secret key: "${secretKey}"`);
      socket.emit('login-success', { token, user: username });
      
      // Don't broadcast users-online here yet - wait until they join the room
      
      const duration = Date.now() - startTime;
      this.log('info', `Login successful`, {
        socketId: socket.id,
        timestamp: new Date().toISOString(),
        userId: username,
        secretKeyValue: secretKey,
        tokenLength: token.length,
        duration: `${duration}ms`,
        totalConnections: this.messageStore.getConnectionCount()
      });
      
    } catch (error: any) {
      const duration = Date.now() - startTime;
      console.error(`💥 [SOCKET-LOGIN] ERROR during login:`, error);
      this.log('error', `Login error occurred`, {
        socketId: socket.id,
        timestamp: new Date().toISOString(),
        error: error.message,
        stack: error.stack,
        duration: `${duration}ms`
      });
      socket.emit('login-error', { error: 'Authentication failed' });
    }
  }

  private handleJoin(socket: Socket): void {
    const user = this.connectedUsers.get(socket.id);
    console.log(`🏠 [JOIN-START] User attempting to join: "${user}", socketId: ${socket.id}`);
    
    if (!user) {
      console.log(`❌ [JOIN-ERROR] No user found for socket: ${socket.id}`);
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }

    console.log(`🏠 [JOIN-PROCESS] User "${user}" joining chat-room...`);
    socket.join('chat-room');
    
    // Send existing messages
    const messages = this.messageStore.getMessages();
    socket.emit('messages-history', messages);
    console.log(`📜 [JOIN] Sent ${messages.length} messages to ${user}`);

    // Broadcast updated online users to ALL clients in the room (including this one)
    console.log(`👥 [JOIN] Broadcasting users-online to all clients:`, Array.from(this.onlineUsers));
    console.log(`👥 [JOIN] Total online users: ${this.onlineUsers.size}`);
    this.io.to('chat-room').emit('users-online', { 
      users: Array.from(this.onlineUsers),
      count: this.onlineUsers.size 
    });

    // Notify other users that someone joined
    socket.to('chat-room').emit('user-joined', { user });
    
    console.log(`✅ [JOIN-SUCCESS] User ${user} joined chat room with ${this.onlineUsers.size} total online`);
  }

  private handleMessage(socket: Socket, data: any): void {
    const user = this.connectedUsers.get(socket.id);
    console.log(`📨 [MESSAGE-HANDLER] Received message from user: "${user}", socketId: ${socket.id}`);
    console.log(`📨 [MESSAGE-HANDLER] Message data:`, {
      type: data?.type,
      contentLength: data?.content?.length,
      seenOnce: data?.seenOnce,
      disappearingPhoto: data?.disappearingPhoto
    });
    
    if (!user) {
      console.log(`❌ [MESSAGE-HANDLER] User not authenticated`);
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }

    try {
      // Validate message data
      const { type, content, seenOnce = false, disappearingPhoto = false, replyTo, duration } = data;
      
      if (!type || !content) {
        console.log(`❌ [MESSAGE-HANDLER] Invalid message data - type: ${type}, content length: ${content?.length}`);
        socket.emit('message-error', { error: 'Invalid message data' });
        return;
      }

      if (type === 'image') {
        // Validate image size (1.5MB limit for Socket.IO stability)
        const sizeInBytes = (content.length * 3) / 4; // Rough base64 size calculation
        const sizeInMB = sizeInBytes / (1024 * 1024);
        console.log(`📸 [MESSAGE-HANDLER] Image size: ${sizeInMB.toFixed(2)}MB`);
        
        if (sizeInBytes > 1.5 * 1024 * 1024) {
          console.log(`❌ [MESSAGE-HANDLER] Image too large: ${sizeInMB.toFixed(2)}MB`);
          socket.emit('message-error', { error: `Image too large (${sizeInMB.toFixed(2)}MB). Max 1.5MB allowed.` });
          return;
        }
        console.log(`✅ [MESSAGE-HANDLER] Image size acceptable: ${sizeInMB.toFixed(2)}MB`);
      }

      // Sanitize text content
      const sanitizedContent = type === 'text' 
        ? this.sanitizeText(content)
        : content;

      const message: Message = {
        id: this.generateMessageId(),
        senderKey: user, // user is now the username
        type,
        content: sanitizedContent,
        timestamp: new Date().toISOString(),
        seenOnce,
        disappearingPhoto,
        replyTo,
        duration
      };

      // Add to store
      const savedMessage = this.messageStore.addMessage(message);
      console.log(`💾 [MESSAGE-HANDLER] Message saved with ID: ${savedMessage.id}`);

      // Send acknowledgment to sender
      socket.emit('message-ack', { messageId: savedMessage.id });
      console.log(`✅ [MESSAGE-HANDLER] Acknowledgment sent to sender`);

      // Broadcast to all users in room
      this.io.to('chat-room').emit('new-message', savedMessage);
      console.log(`📡 [MESSAGE-HANDLER] Message broadcasted to chat-room`);

      console.log(`💬 Message from ${user}: ${type} (${type === 'image' ? 'image data length: ' + content.length : content})`);
    } catch (error) {
      socket.emit('message-error', { error: 'Failed to send message' });
    }
  }

  private handleSeenOnceViewed(socket: Socket, data: { messageId: string }): void {
    const user = this.connectedUsers.get(socket.id);
    if (!user) return;

    const { messageId } = data;
    console.log(`👁️ [SEEN-ONCE] User "${user}" viewed seen-once message: ${messageId}`);
    
    // First, trigger disappearing animation on all clients
    this.io.to('chat-room').emit('message-disappearing', { messageId, type: 'seen-once' });
    console.log(`👁️ [SEEN-ONCE] Triggered disappearing animation for all clients`);
    
    // Then remove the message after animation completes (500ms animation + small buffer)
    setTimeout(() => {
      const removed = this.messageStore.removeSeenOnceMessage(messageId);
      if (removed) {
        this.io.to('chat-room').emit('message-removed', { messageId });
        console.log(`👁️ [SEEN-ONCE] Message ${messageId} removed after animation`);
      }
    }, 600);
  }


  private handlePhotoViewed(socket: Socket, data: { messageId: string }): void {
    const user = this.connectedUsers.get(socket.id);
    if (!user) return;

    const { messageId } = data;
    console.log(`👁️ [PHOTO-VIEWED] User "${user}" viewed disappearing photo: ${messageId}`);
    
    const marked = this.messageStore.markPhotoViewed(messageId);
    
    if (marked) {
      // Notify all clients that photo was viewed (sender gets eye icon update)
      this.io.to('chat-room').emit('photo-viewed', { messageId });
      console.log(`👁️ [PHOTO-VIEWED] Notified all clients that photo ${messageId} was viewed by ${user}`);
      
      // Start 5-second timer, then trigger disappearing animation
      setTimeout(() => {
        console.log(`👁️ [PHOTO-VIEWED] 5 seconds elapsed, triggering disappearing animation for ${messageId}`);
        this.io.to('chat-room').emit('message-disappearing', { messageId, type: 'disappearing-photo' });
        
        // Remove the photo after animation completes
        setTimeout(() => {
          const removed = this.messageStore.removeDisappearingPhoto(messageId);
          if (removed) {
            this.io.to('chat-room').emit('message-removed', { messageId });
            console.log(`👁️ [PHOTO-VIEWED] Photo ${messageId} removed after animation`);
          }
        }, 600);
      }, 5000);
    }
  }

  // WebRTC signaling handlers
  private handleOffer(socket: Socket, data: any): void {
    socket.to('chat-room').emit('offer', data);
  }

  private handleAnswer(socket: Socket, data: any): void {
    socket.to('chat-room').emit('answer', data);
  }

  private handleIceCandidate(socket: Socket, data: any): void {
    socket.to('chat-room').emit('ice-candidate', data);
  }

  private handleCallStart(socket: Socket, data: any): void {
    const user = this.connectedUsers.get(socket.id);
    console.log(`📞 [CALL-START] User "${user}" starting ${data.type} call`);
    
    if (!user) {
      console.error(`❌ [CALL-START] User not authenticated`);
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }
    
    console.log(`📞 [CALL-START] Broadcasting call-start to other users in room`);
    socket.to('chat-room').emit('call-start', { ...data, from: user });
    console.log(`📞 [CALL-START] Call-start event broadcasted`);
  }

  private handleMessageReaction(socket: Socket, data: { messageId: string; emoji: string }): void {
    const user = this.connectedUsers.get(socket.id);
    if (!user) return;

    const { messageId, emoji } = data;
    
    // Broadcast reaction to all clients
    this.io.to('chat-room').emit('message-reaction', { 
      messageId, 
      emoji, 
      user 
    });
    
    console.log(`💖 User ${user} reacted to message ${messageId} with ${emoji}`);
  }

  private handleTyping(socket: Socket, data: { isTyping: boolean }): void {
    const user = this.connectedUsers.get(socket.id);
    if (!user) return;

    const { isTyping } = data;
    
    // Broadcast typing status to other users
    socket.to('chat-room').emit('typing', { 
      user, 
      isTyping 
    });
    
    console.log(`⌨️ User ${user} is ${isTyping ? 'typing' : 'stopped typing'}`);
  }

  private handleCallEnd(socket: Socket): void {
    const user = this.connectedUsers.get(socket.id);
    socket.to('chat-room').emit('call-end', { from: user });
  }

  private handleVideoStateChange(socket: Socket, data: any): void {
    socket.to('chat-room').emit('video-state-change', data);
  }

  private handleHoldStateChange(socket: Socket, data: any): void {
    socket.to('chat-room').emit('hold-state-change', data);
  }

  private handleDisconnect(socket: Socket): void {
    const user = this.connectedUsers.get(socket.id);
    if (user) {
      this.messageStore.removeConnection(user);
      this.connectedUsers.delete(socket.id);
      this.onlineUsers.delete(user);
      
      // Broadcast updated online users
      this.io.to('chat-room').emit('users-online', { 
        users: Array.from(this.onlineUsers),
        count: this.onlineUsers.size 
      });
      
      socket.to('chat-room').emit('user-left', { user });
      console.log(`👋 User ${user} disconnected`);

      // Clear messages if no one is connected
      if (this.messageStore.getConnectionCount() === 0) {
        this.messageStore.clearMessages();
        console.log('🧹 Cleared messages - no active connections');
      }
    }
  }

  private sanitizeText(text: string): string {
    return text
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  private generateMessageId(): string {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}