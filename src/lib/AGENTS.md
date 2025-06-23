# Frontend Security & Utilities Guide
**src/lib/ - Security-Enhanced React Development**

## 🎯 Purpose & Scope

This directory contains critical security utilities, validation functions, API clients, and helper functions for the BlockchainNews frontend. All code here must meet the highest security standards as it handles user inputs, authentication, and sensitive data processing.

---

## 🛡️ Security-Critical Files

### Input Validation & Sanitization (`validators.ts`)

**Purpose**: Prevent XSS, injection attacks, and data corruption
```typescript
import { z } from 'zod'
import DOMPurify from 'dompurify'

// Define strict validation schemas
export const userInputSchemas = {
  email: z.string()
    .email('Invalid email format')
    .max(254, 'Email too long')
    .transform(val => val.trim().toLowerCase()),
    
  password: z.string()
    .min(8, 'Password too short')
    .max(128, 'Password too long')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/, 'Password must contain uppercase, lowercase, number, and special character'),
    
  walletAddress: z.string()
    .regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address')
    .transform(val => ethers.utils.getAddress(val)), // Checksum validation
    
  searchQuery: z.string()
    .max(100, 'Search query too long')
    .transform(val => DOMPurify.sanitize(val.trim()))
}

// CRITICAL: Use for ALL user inputs
export function validateAndSanitize<T>(
  data: unknown, 
  schema: z.ZodSchema<T>
): { success: true; data: T } | { success: false; error: string } {
  try {
    const validated = schema.parse(data)
    return { success: true, data: validated }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { success: false, error: error.errors[0].message }
    }
    return { success: false, error: 'Validation failed' }
  }
}

// XSS-safe content rendering
export function sanitizeHTML(content: string): string {
  return DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['p', 'strong', 'em', 'u', 'br'],
    ALLOWED_ATTR: []
  })
}
```

### Authentication Token Management (`auth-token.ts`)

**Purpose**: Secure token handling without localStorage exposure
```typescript
// CRITICAL: Never use localStorage for tokens in production
class SecureTokenManager {
  private static instance: SecureTokenManager
  private token: string | null = null
  private refreshToken: string | null = null
  private tokenExpiry: number | null = null
  
  private constructor() {
    // Set up cleanup on page unload
    window.addEventListener('beforeunload', () => this.clearTokens())
  }
  
  static getInstance(): SecureTokenManager {
    if (!SecureTokenManager.instance) {
      SecureTokenManager.instance = new SecureTokenManager()
    }
    return SecureTokenManager.instance
  }
  
  setTokens(accessToken: string, refreshToken?: string): void {
    try {
      // Validate token format
      const payload = this.parseJWT(accessToken)
      this.tokenExpiry = payload.exp * 1000
      
      this.token = accessToken
      this.refreshToken = refreshToken
      
      // Schedule automatic cleanup
      this.scheduleTokenCleanup()
    } catch (error) {
      throw new Error('Invalid token format')
    }
  }
  
  getToken(): string | null {
    if (!this.token || !this.tokenExpiry) return null
    
    // Check expiration
    if (Date.now() >= this.tokenExpiry - 60000) { // 1 minute buffer
      this.clearTokens()
      return null
    }
    
    return this.token
  }
  
  clearTokens(): void {
    this.token = null
    this.refreshToken = null
    this.tokenExpiry = null
  }
  
  private parseJWT(token: string): any {
    try {
      const base64Url = token.split('.')[1]
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      )
      return JSON.parse(jsonPayload)
    } catch {
      throw new Error('Invalid JWT format')
    }
  }
  
  private scheduleTokenCleanup(): void {
    if (this.tokenExpiry) {
      const timeUntilExpiry = this.tokenExpiry - Date.now()
      setTimeout(() => this.clearTokens(), timeUntilExpiry)
    }
  }
}

export const secureTokenManager = SecureTokenManager.getInstance()
```

### API Client Security (`api-client.ts`)

**Purpose**: Secure HTTP communication with CSRF protection
```typescript
interface ApiError extends Error {
  status?: number
  code?: string
}

class SecurityError extends Error {
  constructor(message: string, public status?: number) {
    super(message)
    this.name = 'SecurityError'
  }
}

export class SecureApiClient {
  private baseURL: string
  private csrfToken: string | null = null
  
  constructor(baseURL: string) {
    this.baseURL = baseURL
  }
  
  // Initialize CSRF token
  async initializeCSRF(): Promise<void> {
    try {
      const response = await fetch(`${this.baseURL}/api/csrf`, {
        credentials: 'include'
      })
      
      if (!response.ok) {
        throw new SecurityError('Failed to get CSRF token')
      }
      
      const { csrfToken } = await response.json()
      this.csrfToken = csrfToken
    } catch (error) {
      console.error('CSRF initialization failed:', error)
      throw new SecurityError('Security initialization failed')
    }
  }
  
  // Secure fetch with authentication and CSRF protection
  async secureFetch<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const token = secureTokenManager.getToken()
    
    // Validate endpoint to prevent SSRF
    if (!endpoint.startsWith('/api/')) {
      throw new SecurityError('Invalid API endpoint')
    }
    
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // CSRF protection
      ...options.headers
    }
    
    // Add authentication header
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
    
    // Add CSRF token for state-changing operations
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method?.toUpperCase() || '')) {
      if (!this.csrfToken) {
        await this.initializeCSRF()
      }
      headers['X-CSRF-Token'] = this.csrfToken!
    }
    
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        ...options,
        headers,
        credentials: 'include', // Include cookies for session
        mode: 'cors'
      })
      
      // Handle authentication errors
      if (response.status === 401) {
        secureTokenManager.clearTokens()
        throw new SecurityError('Authentication required', 401)
      }
      
      if (response.status === 403) {
        throw new SecurityError('Access denied', 403)
      }
      
      if (!response.ok) {
        throw new SecurityError(`API error: ${response.status}`, response.status)
      }
      
      return await response.json()
    } catch (error) {
      if (error instanceof SecurityError) {
        throw error
      }
      throw new SecurityError('Network error occurred')
    }
  }
  
  // Convenient methods
  async get<T>(endpoint: string): Promise<T> {
    return this.secureFetch<T>(endpoint, { method: 'GET' })
  }
  
  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.secureFetch<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined
    })
  }
  
  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.secureFetch<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined
    })
  }
  
  async delete<T>(endpoint: string): Promise<T> {
    return this.secureFetch<T>(endpoint, { method: 'DELETE' })
  }
}

export const apiClient = new SecureApiClient(
  import.meta.env.VITE_API_URL || 'http://localhost:3001'
)
```

### Web3 Security Utilities (`web3-utils.ts`)

**Purpose**: Secure Web3 interactions and wallet validation
```typescript
import { ethers } from 'ethers'

export class Web3SecurityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'Web3SecurityError'
  }
}

// Secure wallet connection with validation
export async function connectWallet(): Promise<{
  address: string
  chainId: string
  provider: ethers.providers.Web3Provider
}> {
  if (!window.ethereum) {
    throw new Web3SecurityError('MetaMask not detected')
  }
  
  try {
    // Create provider
    const provider = new ethers.providers.Web3Provider(window.ethereum)
    
    // Request account access
    await provider.send('eth_requestAccounts', [])
    
    // Get network info
    const network = await provider.getNetwork()
    const chainId = `0x${network.chainId.toString(16)}`
    
    // Validate we're on a supported network
    const supportedChains = ['0x1', '0x5', '0xaa36a7'] // Mainnet, Goerli, Sepolia
    if (!supportedChains.includes(chainId)) {
      throw new Web3SecurityError('Unsupported network. Please switch to Ethereum Mainnet or testnet.')
    }
    
    // Get account address
    const signer = provider.getSigner()
    const address = await signer.getAddress()
    
    // Validate address format
    if (!ethers.utils.isAddress(address)) {
      throw new Web3SecurityError('Invalid wallet address')
    }
    
    return {
      address: ethers.utils.getAddress(address), // Checksum format
      chainId,
      provider
    }
  } catch (error) {
    if (error instanceof Web3SecurityError) {
      throw error
    }
    throw new Web3SecurityError(`Wallet connection failed: ${error.message}`)
  }
}

// Generate secure sign-in message (EIP-4361 compliant)
export function generateSignInMessage(
  address: string,
  nonce: string,
  timestamp: string
): string {
  const domain = window.location.host
  const origin = window.location.origin
  
  return `${domain} wants you to sign in with your Ethereum account:
${address}

Sign in to BlockchainNews

URI: ${origin}
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${timestamp}`
}

// Verify signed message
export function verifySignature(
  message: string,
  signature: string,
  expectedAddress: string
): boolean {
  try {
    const recoveredAddress = ethers.utils.verifyMessage(message, signature)
    return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase()
  } catch {
    return false
  }
}

// Validate message format and timestamp
export function validateSignInMessage(message: string): {
  isValid: boolean
  address?: string
  nonce?: string
  timestamp?: string
} {
  try {
    const lines = message.split('\n')
    
    // Extract address (line 1)
    const address = lines[1]
    if (!ethers.utils.isAddress(address)) {
      return { isValid: false }
    }
    
    // Extract nonce
    const nonceLine = lines.find(line => line.startsWith('Nonce: '))
    const nonce = nonceLine?.replace('Nonce: ', '')
    if (!nonce || nonce.length < 16) {
      return { isValid: false }
    }
    
    // Extract and validate timestamp
    const timestampLine = lines.find(line => line.startsWith('Issued At: '))
    const timestamp = timestampLine?.replace('Issued At: ', '')
    if (!timestamp) {
      return { isValid: false }
    }
    
    const issueTime = new Date(timestamp).getTime()
    const now = Date.now()
    const fiveMinutes = 5 * 60 * 1000
    
    // Check if message is too old or from future
    if (issueTime < now - fiveMinutes || issueTime > now + fiveMinutes) {
      return { isValid: false }
    }
    
    return {
      isValid: true,
      address: ethers.utils.getAddress(address),
      nonce,
      timestamp
    }
  } catch {
    return { isValid: false }
  }
}
```

---

## 🎨 UI Utility Functions (`ui-utils.ts`)

### Secure Class Name Management
```typescript
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

// Secure className utility
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Safe image loading with fallback
export function getSafeImageUrl(url: string | undefined, fallback: string): string {
  if (!url) return fallback
  
  // Validate URL format
  try {
    new URL(url)
    return url
  } catch {
    return fallback
  }
}

// Secure text truncation
export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text
  return text.slice(0, maxLength).trim() + '...'
}

// Safe date formatting
export function formatDate(date: string | Date): string {
  try {
    const dateObj = typeof date === 'string' ? new Date(date) : date
    if (isNaN(dateObj.getTime())) return 'Invalid date'
    
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(dateObj)
  } catch {
    return 'Invalid date'
  }
}

// Secure price formatting for crypto
export function formatPrice(price: number | string): string {
  try {
    const numPrice = typeof price === 'string' ? parseFloat(price) : price
    if (isNaN(numPrice)) return '$0.00'
    
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 6
    }).format(numPrice)
  } catch {
    return '$0.00'
  }
}

// Secure percentage formatting
export function formatPercentage(value: number | string): string {
  try {
    const numValue = typeof value === 'string' ? parseFloat(value) : value
    if (isNaN(numValue)) return '0.00%'
    
    return new Intl.NumberFormat('en-US', {
      style: 'percent',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(numValue / 100)
  } catch {
    return '0.00%'
  }
}
```

---

## 🔧 Development Guidelines for src/lib/

### File Organization Standards
```
src/lib/
├── validators.ts          # Input validation & sanitization
├── auth-token.ts         # Secure token management
├── api-client.ts         # HTTP client with security
├── web3-utils.ts         # Web3 security utilities  
├── ui-utils.ts          # UI helper functions
├── crypto-utils.ts      # Cryptocurrency utilities
├── storage-utils.ts     # Secure storage abstraction
├── error-handling.ts    # Error management
└── constants.ts         # Application constants
```

### Security Requirements for All Files
1. **Input Validation**: Every function must validate inputs using Zod schemas
2. **Error Handling**: All functions must handle errors gracefully without exposing internals
3. **Type Safety**: Strict TypeScript typing required - no `any` types
4. **Documentation**: JSDoc comments explaining security considerations
5. **Testing**: Unit tests with security-focused test cases

### Code Review Checklist
- [ ] All user inputs validated with Zod schemas
- [ ] No direct localStorage usage (use secure storage utilities)
- [ ] Error messages don't expose sensitive information
- [ ] All network requests include proper security headers
- [ ] Web3 interactions validate addresses and signatures
- [ ] No hardcoded secrets or API keys
- [ ] Proper TypeScript interfaces for all functions
- [ ] Security-focused unit tests included

### Example Security Pattern
```typescript
// GOOD: Secure utility function pattern
export async function secureFunction<T>(
  input: unknown,
  options?: SecurityOptions
): Promise<Result<T, SecurityError>> {
  try {
    // 1. Validate input
    const validated = schema.parse(input)
    
    // 2. Apply security checks
    if (!isAuthorized(validated)) {
      return { success: false, error: new SecurityError('Unauthorized') }
    }
    
    // 3. Process securely
    const result = await processData(validated)
    
    // 4. Return sanitized result
    return { success: true, data: sanitizeOutput(result) }
  } catch (error) {
    // 5. Handle errors securely
    logError(error) // Log for debugging
    return { 
      success: false, 
      error: new SecurityError('Operation failed') // Generic user message
    }
  }
}

// BAD: Insecure patterns to avoid
function insecureFunction(input: any) {
  // ❌ No input validation
  // ❌ Exposing internal errors
  // ❌ No type safety
  return dangerousOperation(input)
}
```

---

## 🧪 Testing Requirements

### Security Test Cases
```typescript
// Example test structure for src/lib/ files
describe('validators.ts Security Tests', () => {
  describe('XSS Prevention', () => {
    it('should sanitize script tags', () => {
      const input = '<script>alert("xss")</script>Hello'
      const result = sanitizeHTML(input)
      expect(result).toBe('Hello')
      expect(result).not.toContain('script')
    })
    
    it('should handle encoded XSS attempts', () => {
      const input = '&lt;script&gt;alert("xss")&lt;/script&gt;'
      const result = sanitizeHTML(input)
      expect(result).not.toContain('script')
    })
  })
  
  describe('Input Validation', () => {
    it('should reject malformed email addresses', () => {
      const result = validateAndSanitize('invalid-email', userInputSchemas.email)
      expect(result.success).toBe(false)
    })
    
    it('should validate Web3 addresses', () => {
      const validAddress = '0x742d35Cc6643C0532925a3b8D9CE8068c2b04c3B'
      const result = validateAndSanitize(validAddress, userInputSchemas.walletAddress)
      expect(result.success).toBe(true)
    })
  })
})
```

### Performance Test Requirements
```typescript
describe('Performance Tests', () => {
  it('should validate large inputs efficiently', () => {
    const largeInput = 'a'.repeat(10000)
    const start = performance.now()
    
    validateAndSanitize(largeInput, userInputSchemas.searchQuery)
    
    const duration = performance.now() - start
    expect(duration).toBeLessThan(100) // Should complete in <100ms
  })
})
```

---

## 🚨 Critical Security Reminders

### Always Remember
1. **Never trust user input** - Validate everything with Zod schemas
2. **Sanitize all output** - Use DOMPurify for HTML content
3. **Handle errors securely** - Never expose internal error details
4. **Use TypeScript strictly** - No `any` types in production code
5. **Test security scenarios** - Include XSS, injection, and edge cases
6. **Log security events** - Track validation failures and suspicious activity

### Common Security Pitfalls to Avoid
```typescript
// ❌ NEVER do this
function badExample(userInput: string) {
  // Direct DOM manipulation without sanitization
  document.innerHTML = userInput
  
  // Exposing internal errors
  throw new Error(`Database connection failed: ${dbPassword}`)
  
  // Using localStorage for tokens
  localStorage.setItem('token', userInput)
  
  // No input validation
  return fetch(`/api/user/${userInput}`)
}

// ✅ ALWAYS do this
function goodExample(userInput: unknown) {
  // Validate input
  const validated = schema.parse(userInput)
  
  // Sanitize output
  const sanitized = DOMPurify.sanitize(validated)
  
  // Secure storage
  secureTokenManager.setToken(validated)
  
  // Parameterized requests
  return apiClient.get(`/api/user/${encodeURIComponent(validated)}`)
}
```

---

## 📋 Development Workflow

### Before Creating New Files
1. Review existing utilities to avoid duplication
2. Design security-first API with input validation
3. Plan comprehensive test coverage
4. Document security considerations

### During Development
1. Write security tests first (TDD approach)
2. Validate all inputs with Zod schemas
3. Handle all error cases gracefully
4. Use TypeScript strictly

### Before Committing
1. Run security test suite: `pnpm test:security`
2. Verify TypeScript compilation: `pnpm type-check`
3. Check linting: `pnpm lint`
4. Review code for security patterns

This directory is the foundation of frontend security - treat every function as if it's protecting user data and preventing attacks.
