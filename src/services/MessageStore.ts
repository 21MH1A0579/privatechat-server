export interface MessageReaction {
  emoji: string;
  user: string;
}

export interface Message {
  id: string;
  senderKey: string; // Keep this for backward compatibility, but it will contain username
  type: 'text' | 'image' | 'voice';
  content: string;
  timestamp: string;
  seenOnce: boolean;
  disappearingPhoto?: boolean; // New field for disappearing photos
  viewedAt?: string; // Timestamp when photo was viewed
  reactions?: MessageReaction[]; // Message reactions
  replyTo?: string; // ID of message being replied to
  duration?: number; // Voice message duration in seconds
}

export class MessageStore {
  private messages: Message[] = [];
  private activeConnections = new Set<string>();
  private readonly MAX_MESSAGES = 10;

  addMessage(message: Message): Message {
    // Add to beginning of array (newest first)
    this.messages.unshift(message);
    
    // Enforce FIFO limit
    if (this.messages.length > this.MAX_MESSAGES) {
      this.messages = this.messages.slice(0, this.MAX_MESSAGES);
    }
    
    return message;
  }

  getMessages(): Message[] {
    return [...this.messages]; // Return copy
  }


  removeSeenOnceMessage(messageId: string): boolean {
    const index = this.messages.findIndex(m => m.id === messageId);
    if (index !== -1) {
      const message = this.messages[index];
      if (message.seenOnce) {
        this.messages.splice(index, 1);
        return true;
      }
    }
    return false;
  }

  markPhotoViewed(messageId: string): boolean {
    const message = this.messages.find(m => m.id === messageId);
    if (message && message.disappearingPhoto) {
      message.viewedAt = new Date().toISOString();
      return true;
    }
    return false;
  }

  removeDisappearingPhoto(messageId: string): boolean {
    const index = this.messages.findIndex(m => m.id === messageId);
    if (index !== -1) {
      const message = this.messages[index];
      if (message.disappearingPhoto) {
        this.messages.splice(index, 1);
        return true;
      }
    }
    return false;
  }

  getExpiredDisappearingPhotos(): string[] {
    const now = new Date().getTime();
    const expiredIds: string[] = [];
    
    this.messages.forEach(message => {
      if (message.disappearingPhoto && message.viewedAt) {
        const viewedTime = new Date(message.viewedAt).getTime();
        if (now - viewedTime >= 30000) { // 30 seconds
          expiredIds.push(message.id);
        }
      }
    });
    
    return expiredIds;
  }

  clearMessages(): void {
    this.messages = [];
  }

  addConnection(userId: string): void {
    this.activeConnections.add(userId);
  }

  removeConnection(userId: string): void {
    this.activeConnections.delete(userId);
  }

  getActiveConnections(): number {
    return this.activeConnections.size;
  }

  hasConnection(userId: string): boolean {
    return this.activeConnections.has(userId);
  }

  getConnectionCount(): number {
    return this.activeConnections.size;
  }
}