import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const VALID_KEYS = ['Chaithu143', 'Geethu143'];

export interface AuthPayload {
  secretKey: string;
  username: string;
  iat: number;
  exp: number;
}

export class AuthService {
  private readonly USER_MAPPING: Record<string, string> = {
    'Chaithu143': 'Chaitanya',
    'Geethu143': 'Geetha'
  };

  validateSecretKey(key: string): boolean {
    console.log(`🔐 Validating secret key: "${key}" - Valid keys: ${VALID_KEYS.join(', ')}`);
    const isValid = VALID_KEYS.includes(key);
    console.log(`🔐 Validation result: ${isValid}`);
    return isValid;
  }

  getUsername(secretKey: string): string {
    const username = this.USER_MAPPING[secretKey] || '';
    console.log(`👤 Mapping "${secretKey}" -> "${username}"`);
    return username;
  }

  // Simple JWT implementation using Node.js crypto (same as Netlify functions)
  generateToken(secretKey: string): string {
    if (!this.validateSecretKey(secretKey)) {
      throw new Error('Invalid secret key');
    }

    const username = this.getUsername(secretKey);
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };

    const payload = {
      secretKey,
      username,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    };

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signature = this.sign(encodedHeader + '.' + encodedPayload, JWT_SECRET);

    return encodedHeader + '.' + encodedPayload + '.' + signature;
  }

  verifyToken(token: string): AuthPayload {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid token format');
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      const expectedSignature = this.sign(encodedHeader + '.' + encodedPayload, JWT_SECRET);

      if (signature !== expectedSignature) {
        throw new Error('Invalid signature');
      }

      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      
      // Check expiration
      if (payload.exp && Date.now() >= payload.exp * 1000) {
        throw new Error('Token expired');
      }

      if (!this.validateSecretKey(payload.secretKey)) {
        throw new Error('Invalid secret key in token');
      }

      return payload;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  private base64UrlEncode(str: string): string {
    return Buffer.from(str)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private base64UrlDecode(str: string): string {
    str += new Array(5 - str.length % 4).join('=');
    return Buffer.from(str.replace(/\-/g, '+').replace(/_/g, '/'), 'base64').toString();
  }

  private sign(data: string, secret: string): string {
    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  getOtherUser(currentUsername: string): string {
    const usernames = Object.values(this.USER_MAPPING);
    return usernames.find(username => username !== currentUsername) || '';
  }
}