export interface JwtPayload {
  exp: number;
  [key: string]: unknown;
}

/**
 * Singleton for secure token management with in-memory storage.
 */
export class SecureTokenManager {
  private static instance: SecureTokenManager;
  private token: string | null = null;
  private refreshToken: string | null = null;

  private constructor() {}

  static getInstance(): SecureTokenManager {
    if (!SecureTokenManager.instance) {
      SecureTokenManager.instance = new SecureTokenManager();
    }
    return SecureTokenManager.instance;
  }

  setTokens(accessToken: string, refreshToken?: string): void {
    this.token = accessToken;
    this.refreshToken = refreshToken || null;
    this.scheduleTokenCleanup();
  }

  getToken(): string | null {
    if (!this.token) return null;
    try {
      const payload = this.parseJWT(this.token);
      if (payload.exp * 1000 < Date.now()) {
        this.clearTokens();
        return null;
      }
      return this.token;
    } catch {
      this.clearTokens();
      return null;
    }
  }

  clearTokens(): void {
    this.token = null;
    this.refreshToken = null;
  }

  private parseJWT(token: string): JwtPayload {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join(''),
    );
    return JSON.parse(jsonPayload) as JwtPayload;
  }

  private scheduleTokenCleanup(): void {
    setTimeout(() => this.clearTokens(), 24 * 60 * 60 * 1000);
  }
}

export default SecureTokenManager;
