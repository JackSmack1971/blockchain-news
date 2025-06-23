# BlockchainNews - Codex Development Guide
**Enterprise Cryptocurrency News Platform with Security-First Architecture**

## 🎯 Project Overview

BlockchainNews is a production-ready cryptocurrency news platform featuring:
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS + shadcn/ui
- **Backend**: Express.js + TypeScript + PostgreSQL  
- **Authentication**: Traditional + Web3 wallet integration
- **Deployment**: https://l9x7q45rab.space.minimax.io

### Critical Security Context
⚠️ **Security Audit Status**: HIGH RISK (85% confidence, 19 findings)
- 3 CRITICAL vulnerabilities requiring immediate attention
- 5 HIGH severity issues affecting production security
- Focus areas: session management, Web3 auth, XSS prevention, CSRF protection

---

## 🚀 Quick Development Setup

### Environment Prerequisites
```bash
# Required versions
node --version    # >= 18.0.0
pnpm --version    # >= 8.0.0
psql --version    # >= 13.0

# Setup commands
pnpm install
cp .env.example .env
chmod +x setup.sh && ./setup.sh
```

### Essential Commands
```bash
# Development
pnpm dev          # Start frontend (port 3000)
pnpm server:dev   # Start backend (port 3001) 
pnpm dev:full     # Start both concurrently

# Quality Assurance
pnpm test                  # Run all tests
pnpm test:security         # Security test suite
pnpm type-check            # TypeScript validation
pnpm lint                  # ESLint + security rules
pnpm audit --audit-level moderate

# Production
pnpm build        # Production build
pnpm preview      # Preview production build
```

---

## 📁 Project Structure Guide

### Key Directories
```
blockchain-news/
├── src/                    # React frontend
│   ├── components/         # Reusable UI components
│   │   ├── layout/         # Header, Footer, MarketTicker  
│   │   ├── pages/          # Page-level components
│   │   ├── ui/             # shadcn/ui components
│   │   └── demo/           # Demo interfaces
│   ├── contexts/           # React Context providers
│   ├── hooks/              # Custom React hooks
│   ├── lib/                # Utilities, validators, APIs
│   └── __tests__/          # Frontend tests
├── server/                 # Express.js backend
│   ├── routes/             # API route handlers
│   ├── middleware/         # Custom middleware
│   ├── __tests__/          # Backend & security tests
│   └── index.ts            # Server entry point
├── public/                 # Static assets & mock data
└── docs/                   # Project documentation
```

### Navigation Tips
```bash
# Jump to specific areas
cd src/components/ui       # shadcn/ui components
cd src/lib                 # Security utilities
cd server/__tests__        # Security test suite
cd public/data             # Mock JSON data
```

---

## 🛡️ Security-First Development Standards

### **CRITICAL**: Address Audit Findings First
Before any new development, prioritize these security fixes:

1. **Session Secret Validation** (SEC-2025-001)
   ```typescript
   // Implement in server/config.ts
   if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
     throw new Error('SESSION_SECRET must be at least 32 characters')
   }
   ```

2. **Web3 Signature Validation** (SEC-2025-002)
   ```typescript
   // Implement EIP-4361 standard in server/routes/auth.ts
   // Add message format validation with domain, timestamp, chain ID
   // Store used signatures to prevent replay attacks
   ```

3. **XSS Protection Enhancement** (SEC-2025-003)
   ```typescript
   // Replace regex sanitization with DOMPurify
   import DOMPurify from 'dompurify'
   const sanitizeInput = (input: string) => DOMPurify.sanitize(input)
   ```

### Security Requirements for All Code
```typescript
// ALWAYS validate inputs with Zod schemas
import { z } from 'zod'
const userSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128)
})

// ALWAYS use parameterized queries
const user = await pool.query(
  'SELECT * FROM users WHERE email = $1', 
  [email]
)

// ALWAYS validate Web3 signatures properly
const message = `Sign-in request for ${domain} at ${timestamp}`
const recoveredAddress = ethers.utils.verifyMessage(message, signature)

// ALWAYS include CSRF protection for state changes
app.use(csrf({ cookie: true }))
```

---

## 🎨 Frontend Development Guidelines

### Component Architecture
```typescript
// Use this structure for all new components
interface ComponentProps {
  // Define strict TypeScript interfaces
}

export const Component: React.FC<ComponentProps> = ({ prop }) => {
  // 1. State management
  const [state, setState] = useState<StateType>()
  
  // 2. Context consumption  
  const { user } = useAuth()
  
  // 3. Side effects
  useEffect(() => {
    // Cleanup functions for security
    return () => cleanup()
  }, [])
  
  // 4. Error boundaries
  if (error) return <ErrorComponent />
  
  // 5. Loading states
  if (loading) return <LoadingSpinner />
  
  // 6. Main render with accessibility
  return (
    <div 
      className="responsive-classes" 
      role="main"
      aria-label="Component description"
    >
      {/* Sanitized content only */}
    </div>
  )
}
```

### Styling Standards
```css
/* Use Tailwind utility classes */
className="
  flex items-center justify-between
  p-4 rounded-lg border border-border
  bg-background text-foreground
  hover:bg-accent transition-colors
  dark:border-gray-700 dark:bg-gray-800
"

/* CSS variables for theming */
:root {
  --background: 0 0% 100%;
  --foreground: 222.2 84% 4.9%;
  --primary: 221.2 83.2% 53.3%;
}
```

### API Integration Security
```typescript
// Always use this pattern for API calls
const apiClient = {
  async fetchWithAuth<T>(url: string, options?: RequestInit): Promise<T> {
    const token = secureTokenManager.getToken()
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': token ? `Bearer ${token}` : '',
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        ...options?.headers
      }
    })
    
    if (!response.ok) {
      throw new SecurityError(`API error: ${response.status}`)
    }
    
    return response.json()
  }
}
```

---

## 🔧 Backend Development Guidelines

### Express.js Security Standards
```typescript
// Required middleware stack (server/index.ts)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}))

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  optionsSuccessStatus: 200
}))

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
}))

// CSRF protection for all POST/PUT/DELETE
if (process.env.NODE_ENV !== 'test') {
  app.use(csrf({ cookie: true }))
}
```

### Database Security
```typescript
// Connection with security validation
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
})

// Always use parameterized queries
const createUser = async (email: string, hashedPassword: string) => {
  const result = await pool.query(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
    [email, hashedPassword]
  )
  return result.rows[0]
}
```

---

## ✅ Testing & Validation Requirements

### Security Test Suite
```bash
# Run before every commit
pnpm test:security

# Individual test categories
pnpm test server/__tests__/auth.security.test.ts
pnpm test server/__tests__/xss.security.test.ts  
pnpm test server/__tests__/csrf.security.test.ts
```

### Pre-Commit Checklist
- [ ] All security tests pass
- [ ] TypeScript compilation successful
- [ ] ESLint security rules pass
- [ ] No console.log statements in production code
- [ ] All user inputs validated and sanitized
- [ ] CSRF tokens included in state-changing operations
- [ ] Authentication checks on protected routes
- [ ] Error messages don't expose sensitive information

### Performance Validation
```bash
# Bundle analysis
pnpm run build && npx vite-bundle-analyzer dist

# Performance testing
pnpm run test:performance

# Lighthouse CI (if configured)
lhci autorun
```

---

## 🚀 Deployment & Production

### Environment Configuration
```bash
# .env.production
NODE_ENV=production
PORT=3001
SESSION_SECRET=<generate-with-crypto.randomBytes(32).toString('hex')>
DATABASE_URL=postgresql://user:pass@host:5432/blockchain_news_prod
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
LOG_LEVEL=warn
FRONTEND_URL=https://blockchain-news.com
COOKIE_SECURE=true
COOKIE_MAX_AGE=86400000
```

### Production Build Optimization
```typescript
// vite.config.ts production settings
export default defineConfig({
  plugins: [react()],
  build: {
    minify: 'esbuild',
    target: 'es2020',
    sourcemap: false, // Security: disable in production
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          charts: ['recharts'],
          crypto: ['ethers']
        }
      }
    }
  }
})
```

---

## 📚 Specialized Development Areas

### Web3 Integration Security
```typescript
// MetaMask connection with validation
const connectWallet = async () => {
  if (!window.ethereum) {
    throw new Error('MetaMask not detected')
  }
  
  // Validate chain ID
  const chainId = await window.ethereum.request({ method: 'eth_chainId' })
  if (chainId !== '0x1') { // Mainnet
    throw new Error('Please switch to Ethereum Mainnet')
  }
  
  // Request account access
  const accounts = await window.ethereum.request({
    method: 'eth_requestAccounts'
  })
  
  return ethers.utils.getAddress(accounts[0]) // Validate address format
}
```

### Real-time Data Security
```typescript
// WebSocket connection with authentication
const connectWebSocket = () => {
  const token = secureTokenManager.getToken()
  if (!token) throw new Error('Authentication required')
  
  const ws = new WebSocket(`wss://api.blockchain-news.com/ws?token=${token}`)
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      // Validate message structure
      if (!isValidWSMessage(data)) {
        throw new Error('Invalid message format')
      }
      handleMessage(data)
    } catch (error) {
      console.error('WebSocket message validation failed:', error)
    }
  }
}
```

---

## 🎯 Code Quality Standards

### TypeScript Configuration
- **Strict mode enabled**: No `any` types allowed
- **Path aliases**: Use `@/` for `src/` imports
- **Interface definitions**: Required for all props and API responses
- **Error handling**: Proper error boundaries and try-catch blocks

### ESLint Security Rules
```json
{
  "extends": [
    "@typescript-eslint/recommended",
    "plugin:security/recommended",
    "plugin:react-hooks/recommended"
  ],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-unsafe-regex": "error",
    "@typescript-eslint/no-any": "error"
  }
}
```

---

## 🆘 Common Troubleshooting

### Development Issues
```bash
# Dependency conflicts
rm -rf node_modules && pnpm install

# TypeScript errors
pnpm run type-check

# Build failures
pnpm run build --verbose

# Test failures
pnpm test --reporter=verbose
```

### Security Issues
```bash
# Audit dependencies
pnpm audit --audit-level moderate

# Security test failures
pnpm test:security --verbose

# HTTPS certificate issues
export NODE_TLS_REJECT_UNAUTHORIZED=0  # Development only!
```

### Performance Issues
```bash
# Bundle size analysis
pnpm run build && ls -la dist/

# React DevTools Profiler
# Enable in development for performance analysis

# Database query optimization
# Check server logs for slow queries
```

---

## 📈 Success Metrics

### Development Velocity
- Zero security test failures
- TypeScript strict mode compliance
- 90%+ test coverage on critical paths
- Sub-3s production build times

### Security Posture  
- All critical audit findings resolved
- OWASP Top 10 compliance
- Regular dependency updates
- Incident-free production deployments

### User Experience
- Lighthouse score >90
- Core Web Vitals compliance
- Accessibility (WCAG 2.1 AA)
- Cross-browser compatibility

---

## 🔗 Additional Resources

- **Security Documentation**: `server/__tests__/AGENTS.md`
- **Frontend Guidelines**: `src/lib/AGENTS.md`
- **API Documentation**: `server/AGENTS.md`
- **Deployment Guide**: `README.md`
- **Live Demo**: https://l9x7q45rab.space.minimax.io

---

**Remember**: Security is not optional. Every line of code must consider the security implications, especially given our HIGH RISK audit status. When in doubt, fail securely and validate extensively.
