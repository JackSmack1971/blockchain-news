# BlockchainNews Codex Setup Guide

## Quick Setup for Codex Environment

### 1. Python Requirements (requirements.txt)
```
setuptools>=60.0.0
wheel>=0.37.0
pip>=22.0.0
requests>=2.28.0
python-dotenv>=1.0.0
```

### 2. Environment Setup Script
Run this in the Codex environment:
```bash
chmod +x setup.sh && ./setup.sh
```

### 3. Manual Setup (if script fails)

#### Install Dependencies
```bash
# Install pnpm (if not available)
npm install -g pnpm

# Install project dependencies
pnpm install

# Create environment file
cp .env.example .env

# Generate a secure session secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

#### Environment Variables (.env)
```bash
NODE_ENV=development
PORT=3001
SESSION_SECRET=<use generated session secret>
DATABASE_URL=postgresql://codex:password@localhost:5432/blockchain_news_dev
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
LOG_LEVEL=info
FRONTEND_URL=http://localhost:3000
COOKIE_SECURE=false
COOKIE_MAX_AGE=86400000
```

### 4. Verify Setup
```bash
# Check environment
node -e "console.log('Node:', process.version); console.log('Env loaded:', !!process.env.SESSION_SECRET)"

# Install and build
pnpm install && pnpm build

# Run tests
pnpm test
```

## Project Structure for Codex

### Key Directories
- `src/` - React frontend (TypeScript + Tailwind + shadcn/ui)
- `server/` - Express backend (TypeScript + PostgreSQL)
- `src/components/` - Reusable React components
- `src/lib/` - Utilities, validators, API clients
- `server/__tests__/` - Security and integration tests

### Important Files
- `AGENTS.md` - Main development guide
- `package.json` - Node.js dependencies and scripts
- `vite.config.ts` - Build configuration
- `tsconfig.json` - TypeScript configuration
- `server/index.ts` - Express server entry point

## Codex Development Guidelines

### Security-First Development
1. **Always** implement input validation
2. **Always** use parameterized database queries
3. **Always** validate Web3 signatures properly
4. **Always** include CSRF protection for state changes
5. **Always** sanitize user inputs to prevent XSS

### TypeScript Best Practices
- Use strict typing throughout
- Define interfaces for all data structures
- Use utility types for better type safety
- Include comprehensive error handling

### Performance Optimization
- Use React.memo for expensive components
- Implement proper useMemo/useCallback patterns
- Use React 18 concurrent features
- Optimize bundle size with code splitting

### Web3 Integration Patterns
- Validate Ethereum addresses before processing
- Use nonce-based authentication for signatures
- Implement proper error handling for wallet operations
- Support multiple wallet providers (MetaMask, WalletConnect)

## Common Development Tasks

### Create New Component
```bash
# Ask Codex:
"Create a secure crypto price display component with TypeScript interfaces and proper error handling"
```

### Add API Endpoint
```bash
# Ask Codex:
"Add a rate-limited API endpoint with CSRF protection and input validation for user profile updates"
```

### Implement Authentication
```bash
# Ask Codex:
"Implement Web3 wallet authentication with signature validation following the security patterns in AGENTS.md"
```

### Add Tests
```bash
# Ask Codex:
"Write comprehensive security tests for the authentication endpoints including XSS and CSRF protection"
```

### Optimize Performance
```bash
# Ask Codex:
"Optimize the real-time market data streaming component with React 18 concurrent features and proper memory management"
```

## Troubleshooting

### Common Issues

1. **Node modules compilation errors**
   ```bash
   npm rebuild
   # or
   rm -rf node_modules && pnpm install
   ```

2. **TypeScript errors**
   ```bash
   pnpm run type-check
   # Clean TypeScript cache
   rm -rf node_modules/.cache
   ```

3. **Database connection issues**
   ```bash
   # Check PostgreSQL service
   pg_isready
   # Test connection
   psql $DATABASE_URL -c "SELECT 1"
   ```

4. **Port conflicts**
   ```bash
   # Check what's using ports
   lsof -i :3000 -i :3001
   ```

5. **Security test failures**
   ```bash
   # Reset test environment
   pnpm run test:setup
   ```

## Environment Validation

Before starting development, ensure:
- ✅ Node.js 18+ installed
- ✅ pnpm package manager available
- ✅ PostgreSQL running (optional for frontend-only development)
- ✅ Environment variables configured
- ✅ Dependencies installed successfully
- ✅ TypeScript compilation working
- ✅ Tests passing

## Performance Targets

### Development
- Hot reload: < 500ms
- TypeScript compilation: < 2s
- Test execution: < 10s

### Runtime
- Initial load: < 3s
- Chart updates: < 100ms
- API responses: < 200ms
- Authentication: < 500ms

## Security Checklist

Before any deployment or major changes:
- ✅ All inputs validated and sanitized
- ✅ CSRF protection enabled
- ✅ Rate limiting configured
- ✅ Session security implemented
- ✅ Web3 signatures properly validated
- ✅ Database queries parameterized
- ✅ Security headers configured
- ✅ Audit clean (no high-severity vulnerabilities)

## Codex Usage Tips

1. **Reference AGENTS.md** - Always mention following patterns from AGENTS.md
2. **Security First** - Prioritize security in all implementations
3. **TypeScript Strict** - Use comprehensive typing
4. **Test Coverage** - Include tests for security-critical functions
5. **Performance Aware** - Consider performance implications
6. **Web3 Compatible** - Ensure blockchain integration compatibility
