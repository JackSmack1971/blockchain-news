# Frontend Security Utilities Guidelines

## Library Architecture Overview

The `src/lib/` directory contains critical frontend security utilities including input validation, API clients, authentication helpers, and data sanitization functions that work in conjunction with the backend security measures.

### Key Security Modules
- **`validators.ts`**: Client-side input validation and sanitization
- **`authToken.ts`**: Secure token management and Web3 authentication
- **`api.ts`**: Secure API client with request/response handling
- **`sanitizeHtml.ts`**: XSS prevention and content sanitization
- **`errors.ts`**: Secure error handling and user-safe error messages
- **`crypto.ts`**: Client-side cryptographic utilities for Web3

## Input Validation and Sanitization (`validators.ts`)

### Wallet Address Validation
```typescript
import { ethers } from 'ethers';

// Ethereum address validation with EIP-55 checksum
export function isValidEthereumAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return false;
  
  // Basic format check
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return false;
  
  // EIP-55 checksum validation
  try {
    const checksumAddress = ethers.getAddress(address);
    return address === checksumAddress;
  } catch {
    return false;
  }
}
```

### Form Input Validation
```typescript
// Comprehensive form validation with security focus
export const validationRules = {
  username: {
    required: true,
    minLength: 3,
    maxLength: 30,
    pattern: /^[a-zA-Z0-9_-]+$/,
    sanitize: (value: string) => value.trim().toLowerCase(),
  },
  email: {
    required: true,
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    maxLength: 254,
    sanitize: (value: string) => value.trim().toLowerCase(),
  },
  password: {
    required: true,
    minLength: 8,
    maxLength: 128,
    pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
  },
};

// Secure validation function with sanitization
export function validateInput(value: string, rules: ValidationRule): ValidationResult {
  const sanitized = rules.sanitize ? rules.sanitize(value) : value;
  
  // XSS prevention - reject dangerous patterns
  const dangerousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /data:text\/html/gi,
  ];
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      return { isValid: false, error: 'Invalid characters detected' };
    }
  }
  
  // Apply other validation rules
  if (rules.required && !sanitized) {
    return { isValid: false, error: 'This field is required' };
  }
  
  if (rules.minLength && sanitized.length < rules.minLength) {
    return { isValid: false, error: `Minimum length is ${rules.minLength}` };
  }
  
  if (rules.maxLength && sanitized.length > rules.maxLength) {
    return { isValid: false, error: `Maximum length is ${rules.maxLength}` };
  }
  
  if (rules.pattern && !rules.pattern.test(sanitized)) {
    return { isValid: false, error: 'Invalid format' };
  }
  
  return { isValid: true, value: sanitized };
}
```

## Authentication Token Management (`authToken.ts`)

### Secure Token Storage
```typescript
// Secure token management without localStorage exposure
class SecureTokenManager {
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
  
  // Store tokens securely (memory only, not localStorage)
  setTokens(accessToken: string, refreshToken?: string): void {
    this.token = accessToken;
    this.refreshToken = refreshToken;
    
    // Set up automatic cleanup
    this.scheduleTokenCleanup();
  }
  
  // Get token with validation
  getToken(): string | null {
    if (!this.token) return null;
    
    try {
      // Validate token format and expiration
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
  
  // Secure token cleanup
  clearTokens(): void {
    this.token = null;
    this.refreshToken = null;
  }
  
  private parseJWT(token: string): any {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  }
  
  private scheduleTokenCleanup(): void {
    // Clean up tokens after 24 hours
    setTimeout(() => this.clearTokens(), 24 * 60 * 60 * 1000);
  }
}
```

### Web3 Authentication Utilities
```typescript
import { ethers } from 'ethers';

// Secure Web3 authentication helpers
export class Web3AuthManager {
  private wallet: ethers.Wallet | null = null;
  
  // Connect to Web3 wallet securely
  async connectWallet(): Promise<{ address: string; signer: ethers.Signer }> {
    if (!window.ethereum) {
      throw new Error('Web3 wallet not detected');
    }
    
    try {
      const provider = new ethers.BrowserProvider(window.ethereum);
      await provider.send('eth_requestAccounts', []);
      const signer = await provider.getSigner();
      const address = await signer.getAddress();
      
      // Validate address format
      if (!isValidEthereumAddress(address)) {
        throw new Error('Invalid wallet address format');
      }
      
      return { address, signer };
    } catch (error) {
      throw new Error(`Wallet connection failed: ${error.message}`);
    }
  }
  
  // Sign authentication message securely
  async signAuthMessage(nonce: string, address: string): Promise<string> {
    if (!window.ethereum) {
      throw new Error('Web3 wallet not available');
    }
    
    const provider = new ethers.BrowserProvider(window.ethereum);
    const signer = await provider.getSigner();
    
    // Create secure message format
    const message = `BlockchainNews Authentication\nNonce: ${nonce}\nAddress: ${address}\nTimestamp: ${Date.now()}`;
    
    try {
      const signature = await signer.signMessage(message);
      
      // Validate signature format
      if (!/^0x[a-fA-F0-9]{130}$/.test(signature)) {
        throw new Error('Invalid signature format');
      }
      
      return signature;
    } catch (error) {
      throw new Error(`Message signing failed: ${error.message}`);
    }
  }
}
```

## API Client Security (`api.ts`)

### Secure HTTP Client
```typescript
// Secure API client with comprehensive error handling
class SecureApiClient {
  private baseUrl: string;
  private tokenManager: SecureTokenManager;
  
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
    this.tokenManager = SecureTokenManager.getInstance();
  }
  
  // Secure request method with automatic retry and error handling
  async request<T>(
    endpoint: string,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseUrl}${endpoint}`;
    const token = this.tokenManager.getToken();
    
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
    
    // Add authentication if available
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    
    // Request configuration with security headers
    const config: RequestInit = {
      method: options.method || 'GET',
      headers,
      credentials: 'include', // Include cookies for session management
      mode: 'cors',
      ...options,
    };
    
    // Add body for non-GET requests
    if (options.body && config.method !== 'GET') {
      config.body = JSON.stringify(options.body);
    }
    
    try {
      const response = await fetch(url, config);
      
      // Handle authentication errors
      if (response.status === 401) {
        this.tokenManager.clearTokens();
        throw new AuthenticationError('Authentication required');
      }
      
      // Handle rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        throw new RateLimitError(`Rate limited. Retry after ${retryAfter} seconds`);
      }
      
      // Parse response securely
      const data = await this.parseResponse<T>(response);
      
      return {
        data,
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
      };
    } catch (error) {
      if (error instanceof TypeError) {
        throw new NetworkError('Network request failed');
      }
      throw error;
    }
  }
  
  private async parseResponse<T>(response: Response): Promise<T> {
    const contentType = response.headers.get('content-type');
    
    if (!contentType?.includes('application/json')) {
      throw new Error('Invalid response format');
    }
    
    try {
      const text = await response.text();
      
      // Validate JSON before parsing
      if (!text.trim()) {
        throw new Error('Empty response');
      }
      
      return JSON.parse(text);
    } catch (error) {
      throw new Error('Failed to parse response');
    }
  }
}
```

## Content Sanitization (`sanitizeHtml.ts`)

### XSS Prevention
```typescript
// Comprehensive HTML sanitization for user content
export function sanitizeHtml(input: string): string {
  if (!input || typeof input !== 'string') return '';
  
  // Remove dangerous tags and attributes
  const dangerousPatterns = [
    // Script tags
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    // Event handlers
    /on\w+\s*=\s*["'][^"']*["']/gi,
    // JavaScript URLs
    /javascript:\s*[^"';\s]*/gi,
    // Data URLs with HTML
    /data:text\/html[^"';\s]*/gi,
    // Style tags with expressions
    /<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi,
  ];
  
  let sanitized = input;
  
  // Remove dangerous patterns
  dangerousPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '');
  });
  
  // HTML entity encoding for remaining content
  const entityMap: { [key: string]: string } = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
  };
  
  return sanitized.replace(/[&<>"'\/]/g, (char) => entityMap[char]);
}

// Sanitize user input for display
export function sanitizeUserInput(input: string): string {
  return sanitizeHtml(input).trim().substring(0, 1000); // Limit length
}

// Sanitize URLs to prevent XSS
export function sanitizeUrl(url: string): string {
  if (!url || typeof url !== 'string') return '';
  
  // Allow only safe protocols
  const safeProtocols = ['http:', 'https:', 'mailto:'];
  
  try {
    const urlObj = new URL(url);
    
    if (!safeProtocols.includes(urlObj.protocol)) {
      return '';
    }
    
    return urlObj.toString();
  } catch {
    return '';
  }
}
```

## Error Handling (`errors.ts`)

### Secure Error Classes
```typescript
// Security-focused error classes that don't expose sensitive information
export class SecurityError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

export class ValidationError extends SecurityError {
  constructor(message: string, public field?: string) {
    super(message, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends SecurityError {
  constructor(message: string = 'Authentication required') {
    super(message, 'AUTH_ERROR');
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends SecurityError {
  constructor(message: string) {
    super(message, 'RATE_LIMIT_ERROR');
    this.name = 'RateLimitError';
  }
}

// Safe error handler that doesn't expose sensitive information
export function handleSecureError(error: unknown): { message: string; code?: string } {
  if (error instanceof SecurityError) {
    return {
      message: error.message,
      code: error.code,
    };
  }
  
  if (error instanceof Error) {
    // Log full error for debugging but return generic message
    console.error('Unexpected error:', error);
    return {
      message: 'An unexpected error occurred',
      code: 'UNKNOWN_ERROR',
    };
  }
  
  return {
    message: 'An error occurred',
    code: 'GENERIC_ERROR',
  };
}
```

## React Component Security Patterns

### Secure State Management
```typescript
import { useState, useEffect } from 'react';

// Secure authentication state management
export function useAuthState() {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  
  useEffect(() => {
    let ignore = false;
    
    async function validateSession() {
      try {
        const response = await apiClient.get('/api/me');
        if (!ignore) {
          setUser(response.data);
        }
      } catch (error) {
        if (!ignore) {
          setUser(null);
        }
      } finally {
        if (!ignore) {
          setIsLoading(false);
        }
      }
    }
    
    validateSession();
    return () => { ignore = true; };
  }, []);
  
  return { user, isLoading };
}
```

### Secure Form Handling
```typescript
import { useState } from 'react';

export function useSecureForm<T>(initialValues: T, validationRules: ValidationRules<T>) {
  const [values, setValues] = useState<T>(initialValues);
  const [errors, setErrors] = useState<Partial<T>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  const validateField = (name: keyof T, value: string) => {
    const rule = validationRules[name];
    if (rule) {
      const result = validateInput(value, rule);
      setErrors(prev => ({
        ...prev,
        [name]: result.isValid ? undefined : result.error
      }));
      return result.isValid;
    }
    return true;
  };
  
  const handleChange = (name: keyof T, value: string) => {
    const rule = validationRules[name];
    const sanitizedValue = rule?.sanitize ? rule.sanitize(value) : value;
    
    setValues(prev => ({ ...prev, [name]: sanitizedValue }));
    validateField(name, sanitizedValue);
  };
  
  const handleSubmit = async (onSubmit: (values: T) => Promise<void>) => {
    if (isSubmitting) return;
    
    setIsSubmitting(true);
    try {
      await onSubmit(values);
    } catch (error) {
      console.error('Form submission error:', error);
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return {
    values,
    errors,
    isSubmitting,
    handleChange,
    handleSubmit,
    validateField,
  };
}
```

## Testing Frontend Security

### Validation Testing Patterns
```typescript
import { describe, it, expect } from 'vitest';

describe('Input Validation', () => {
  it('validates Ethereum addresses correctly', () => {
    // Valid addresses
    expect(isValidEthereumAddress('0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d0')).toBe(true);
    
    // Invalid addresses
    expect(isValidEthereumAddress('not-an-address')).toBe(false);
    expect(isValidEthereumAddress('0xinvalid')).toBe(false);
    expect(isValidEthereumAddress('')).toBe(false);
    expect(isValidEthereumAddress(null as any)).toBe(false);
  });
  
  it('sanitizes XSS attempts', () => {
    const xssInput = '<script>alert("xss")</script>';
    const sanitized = sanitizeHtml(xssInput);
    expect(sanitized).not.toContain('<script>');
    expect(sanitized).not.toContain('alert');
  });
});
```

## Security Best Practices

### Client-Side Security Checklist
- [ ] All user inputs validated and sanitized
- [ ] No sensitive data stored in localStorage
- [ ] Secure token management implemented
- [ ] XSS prevention in place
- [ ] URL validation for external links
- [ ] Error handling doesn't expose sensitive info
- [ ] Web3 authentication properly implemented
- [ ] API requests include proper headers
- [ ] Content Security Policy compliance
- [ ] Input length limits enforced

### Performance Considerations
- **Validation**: Client-side validation for UX, server-side for security
- **Sanitization**: Minimal client-side sanitization, comprehensive server-side
- **Token Management**: Memory-based storage for security
- **API Calls**: Proper caching and request deduplication

---

## Integration with Backend Security

### Authentication Flow
1. **Frontend**: Collect credentials, validate format
2. **Frontend**: Send to backend API with proper headers
3. **Backend**: Validate, authenticate, create session
4. **Frontend**: Store session data securely
5. **Frontend**: Include auth headers in subsequent requests

### Error Handling Integration
- **Frontend**: Display user-friendly error messages
- **Backend**: Log detailed security events
- **Frontend**: Never expose internal error details
- **Backend**: Return consistent error formats

Remember: Frontend security is about user experience and preventing simple attacks. Real security enforcement happens on the backend.
