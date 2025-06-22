# Security Remediation Guidelines

## Priority Framework
1. Address CRITICAL security issues first (authentication, encryption)
2. Implement HIGH security fixes (XSS, validation, cookies)
3. Apply MEDIUM improvements (performance, dependencies, HTTPS)
4. Complete LOW priority enhancements (logging, testing)

## Code Standards
- Use TypeScript strict mode for all new security implementations
- Implement proper error handling with specific error types
- Add comprehensive JSDoc comments for security-critical functions
- Follow OWASP security best practices for web applications

## Verification Requirements
- Run `npm test` after each security fix
- Verify all authentication flows manually
- Test edge cases and malicious input scenarios
- Confirm proper cookie security settings in browser dev tools

## Security Implementation Rules
- Never store sensitive data in localStorage or unencrypted cookies
- Always validate and sanitize user inputs server-side
- Implement proper HTTPS enforcement for production
- Use Content Security Policy headers to prevent XSS
- Apply principle of least privilege for all access controls

## Pull Request Guidelines
- Title format: [SECURITY] Brief description of fix
- Include security impact assessment in PR description
- Reference specific audit finding ID (e.g., SEC-2025-001)
- Provide before/after security comparison
- Include verification steps in PR description
