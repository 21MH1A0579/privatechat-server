export interface Message {
  id: string;
  senderKey: string; // Keep this for backward compatibility, but it will contain username
  type: 'text' | 'image';
  content: string;
  timestamp: string;
  seen: boolean;
  seenOnce: boolean;
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

  markMessageSeen(messageId: string): boolean {
    const message = this.messages.find(m => m.id === messageId);
    if (message) {
      message.seen = true;
      return true;
    }
    return false;
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