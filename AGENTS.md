# BlockchainNews - Security-Enhanced Development Guidelines

## Project Overview

BlockchainNews is a production-ready cryptocurrency news platform built with modern web technologies and comprehensive security measures. This React + TypeScript application features real-time market data, Web3 authentication, and enterprise-grade security implementations.

### Technology Stack
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui
- **Backend**: Node.js, Express, PostgreSQL, session management
- **Authentication**: Traditional email/password + Web3 wallet integration
- **Testing**: Vitest, Supertest, comprehensive security test suite
- **Build**: pnpm, Vite optimization, production deployment ready

## Repository Structure Navigation

```
blockchain-news/
├── src/                    # React frontend application
│   ├── components/         # Reusable UI components
│   ├── pages/             # Route-based page components
│   ├── lib/               # Utilities, validators, API clients
│   └── __tests__/         # Frontend unit tests
├── server/                # Express backend API
│   ├── __tests__/         # Backend integration & security tests
│   ├── db.ts             # PostgreSQL database configuration
│   └── index.ts          # Main server application
├── public/               # Static assets and mock data
└── docs/                 # Project documentation
```

### Key Navigation Tips
- Use `pnpm dev` for development server (frontend + backend)
- Database tests require PostgreSQL running locally
- Security tests: `pnpm run test:security`
- Full test suite: `pnpm test`
- Production build: `pnpm build`

## Security-First Development Approach

### CRITICAL Security Rules
1. **Authentication**: Never bypass cryptographic verification for wallet-based authentication
2. **Session Management**: Always use whitelisted properties for session updates  
3. **Input Validation**: Validate all inputs server-side with proper schemas
4. **Security Headers**: Maintain comprehensive security header configuration
5. **Database Security**: Use parameterized queries and proper connection management

### Security Testing Requirements
- **Mandatory**: Run `pnpm run test:security` before any commit
- **Verification**: `pnpm audit` must show no high/critical vulnerabilities
- **Manual Testing**: Test all authentication flows in browser
- **Header Validation**: Check security headers in browser dev tools

## Development Workflow

### Environment Setup
```bash
# Install dependencies
pnpm install

# Start development (frontend + backend)
pnpm dev

# Database setup (PostgreSQL required)
# Ensure DATABASE_URL environment variable is set
```

### Testing Procedures
```bash
# Security tests (REQUIRED before commits)
pnpm run test:security

# Full test suite
pnpm test

# Focus on specific test with Vitest
pnpm vitest run -t "<test name>"

# Lint and type checking
pnpm lint
pnpm type-check
```

### Database Management
- **Test Database**: Uses PostgreSQL with isolated test environments
- **Connection Pooling**: Configured for development and testing
- **Cleanup Functions**: `resetUsers()`, `resetNonces()`, `resetLoginAttempts()`
- **Constraints**: Watch for PostgreSQL type conflicts in tests

## Code Standards and Practices

### TypeScript Requirements
- **Strict Mode**: All new code must use TypeScript strict mode
- **Type Safety**: Define proper interfaces for all data structures
- **Error Handling**: Use specific error types (DatabaseError, ValidationError)
- **Documentation**: JSDoc comments required for security-critical functions

### React Patterns
```typescript
// Proper useState with TypeScript
const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

// useEffect with cleanup for data fetching
useEffect(() => {
  let ignore = false;
  
  async function fetchData() {
    const result = await fetch('/api/data');
    if (!ignore) {
      setData(result);
    }
  }
  
  fetchData();
  return () => { ignore = true; };
}, [dependency]);
```

### Security Implementation Patterns
```typescript
// Authentication validation example
interface WalletLoginRequest {
  walletAddress: string;
  signature: string;
  nonce: string;
}

// Proper error handling
try {
  await validateWalletSignature(request);
} catch (error) {
  if (error instanceof ValidationError) {
    return res.status(400).json({ error: error.message });
  }
  throw error;
}
```

### Testing Standards
- **Test Structure**: Arrange-Act-Assert pattern with Vitest
- **Security Focus**: Include edge cases and malicious input scenarios
- **Database Tests**: Proper setup/teardown with isolated environments
- **Mocking**: Use consistent mocking patterns for external APIs

## Web3 and Blockchain Specific Guidelines

### Authentication Flow
1. **Nonce Generation**: Server generates cryptographic nonce
2. **Signature Request**: Client signs nonce with wallet
3. **Verification**: Server verifies signature cryptographically
4. **Session Creation**: Secure session establishment

### Market Data Integration
- **API Endpoints**: CoinGecko, CoinMarketCap integration points
- **Rate Limiting**: Respect API rate limits and implement caching
- **Error Handling**: Graceful degradation when APIs unavailable
- **Security**: Validate all external data before processing

## Verification and Quality Assurance

### Pre-Commit Checklist
- [ ] Security tests pass: `pnpm run test:security`
- [ ] Full test suite passes: `pnpm test`
- [ ] No linting errors: `pnpm lint`
- [ ] Type checking clean: `pnpm type-check`
- [ ] No high/critical audit issues: `pnpm audit`
- [ ] Manual authentication testing completed
- [ ] Security headers verified in browser

### Code Review Requirements
- [ ] No hardcoded secrets or credentials
- [ ] All user inputs validated and sanitized
- [ ] Security headers not modified without security review
- [ ] Database queries use parameterized statements
- [ ] Authentication flows include proper verification
- [ ] Rate limiting applied to sensitive endpoints

## Pull Request Guidelines

### Title Format
```
[SECURITY] Brief description of security fix
[FEATURE] New feature implementation
[BUGFIX] Bug fix description
[REFACTOR] Code refactoring
```

### Description Template
```markdown
## Security Impact Assessment
- Authentication: [Impact description]
- Data Protection: [Impact description]
- Attack Prevention: [Impact description]

## Changes Made
- List specific security improvements
- Reference audit findings addressed
- Include before/after security comparison

## Verification Steps
- [ ] Security tests pass
- [ ] Manual authentication testing
- [ ] Browser security header validation
- [ ] Performance impact assessment

## Additional Notes
- Any breaking changes
- Migration requirements
- Monitoring considerations
```

## Security Incident Response

### Detection and Response
1. **Monitor**: Security logs at `logs/security.log`
2. **Assess**: Evaluate scope and impact
3. **Respond**: Follow incident response playbook
4. **Recover**: Implement fixes and verify integrity
5. **Review**: Document lessons learned

### Emergency Contacts
- **Security Team**: [Define contact method]
- **Database Admin**: [Define contact method]
- **DevOps Lead**: [Define contact method]

## Performance and Optimization

### Build Optimization
- **Vite Configuration**: Optimized for production builds
- **Code Splitting**: Implement lazy loading for large components
- **Asset Optimization**: Images and static assets properly cached
- **Bundle Analysis**: Regular bundle size monitoring

### Database Performance
- **Connection Pooling**: Properly configured for load
- **Query Optimization**: Use indexes and efficient queries
- **Caching Strategy**: Implement appropriate caching layers
- **Monitoring**: Track database performance metrics

## Deployment and Production

### Environment Configuration
- **HTTPS Enforcement**: Required for production
- **Environment Variables**: All secrets properly configured
- **Database Migration**: Proper migration procedures
- **Security Headers**: Production security configuration

### Monitoring and Alerting
- **Security Events**: Real-time security monitoring
- **Performance Metrics**: Application performance tracking
- **Error Tracking**: Comprehensive error reporting
- **User Analytics**: Privacy-compliant usage analytics

## Troubleshooting Common Issues

### Database Test Failures
```bash
# PostgreSQL constraint violations
# Solution: Ensure proper test database cleanup
pnpm run test:security --reporter=verbose

# Check database connection
psql $DATABASE_URL -c "SELECT 1;"
```

### Authentication Issues
- **Web3 Signature Validation**: Check nonce generation and verification
- **Session Management**: Verify cookie configuration and security
- **Rate Limiting**: Check rate limiter configuration

### Build and Development Issues
- **Dependency Conflicts**: Use `pnpm install --frozen-lockfile`
- **Type Errors**: Run `pnpm type-check` for detailed TypeScript errors
- **Port Conflicts**: Ensure ports 3000 (frontend) and 3001 (backend) available

---

## Additional Resources

- **Security Documentation**: `/docs/security/`
- **API Documentation**: `/docs/api/`
- **Development Setup**: `/docs/development/`
- **Deployment Guide**: `/docs/deployment/`

Remember: Security is everyone's responsibility. When in doubt, choose the more secure option and consult the security team.
