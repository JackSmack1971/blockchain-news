# React Component Security & Development Guide
**src/components/ - Security-Enhanced Component Architecture**

## 🎯 Purpose & Component Security Philosophy

This directory contains all React components for the BlockchainNews platform. Every component must implement security-first patterns, proper TypeScript typing, accessibility standards, and performance optimizations while maintaining the existing shadcn/ui design system.

**Security Principle**: Components are the user-facing attack surface - they must validate, sanitize, and secure all user interactions.

---

## 📁 Component Directory Structure

```
src/components/
├── layout/                 # App structure components
│   ├── Header.tsx         # Main navigation with market ticker
│   ├── Footer.tsx         # Site footer
│   ├── MarketTicker.tsx   # Real-time crypto prices
│   └── Sidebar.tsx        # Navigation sidebar
├── pages/                 # Page-level components
│   ├── HomePage.tsx       # Landing page
│   ├── ArticlePage.tsx    # Individual article view
│   ├── CategoryPage.tsx   # Category listing
│   ├── SearchPage.tsx     # Search results
│   └── ProfilePage.tsx    # User profile
├── ui/                    # shadcn/ui components
│   ├── button.tsx         # Button primitives
│   ├── input.tsx          # Form inputs
│   ├── dialog.tsx         # Modal dialogs
│   ├── dropdown-menu.tsx  # Dropdown menus
│   ├── card.tsx           # Content cards
│   └── ...                # Other shadcn/ui components
├── forms/                 # Form components with validation
│   ├── LoginForm.tsx      # Authentication form
│   ├── RegisterForm.tsx   # User registration
│   ├── CommentForm.tsx    # Article comments
│   └── SearchForm.tsx     # Search input
├── features/              # Feature-specific components
│   ├── auth/              # Authentication components
│   ├── articles/          # Article-related components
│   ├── comments/          # Comment system
│   ├── wallet/            # Web3 wallet integration
│   └── bookmarks/         # Bookmark functionality
└── demo/                  # Demo/prototype components
    └── BlockchainNewsInterface.tsx
```

---

## 🛡️ Security-First Component Patterns

### **1. Input Validation & Sanitization Template**

```typescript
// components/forms/SecureForm.tsx - Base pattern for all forms
import React, { useState } from 'react'
import { z } from 'zod'
import DOMPurify from 'dompurify'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { validateAndSanitize } from '@/lib/validators'

interface SecureFormProps {
  onSubmit: (data: any) => Promise<void>
  schema: z.ZodSchema
  children: React.ReactNode
}

export const SecureForm: React.FC<SecureFormProps> = ({ 
  onSubmit, 
  schema, 
  children 
}) => {
  const [formData, setFormData] = useState<Record<string, string>>({})
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleInputChange = (field: string, value: string) => {
    // Immediate XSS protection
    const sanitized = DOMPurify.sanitize(value, { 
      ALLOWED_TAGS: [], 
      ALLOWED_ATTR: [] 
    })
    
    setFormData(prev => ({ ...prev, [field]: sanitized }))
    
    // Clear previous error
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }))
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    
    try {
      // Validate with Zod schema
      const result = validateAndSanitize(formData, schema)
      
      if (!result.success) {
        setErrors({ general: result.error })
        return
      }
      
      await onSubmit(result.data)
    } catch (error) {
      setErrors({ 
        general: error instanceof Error 
          ? error.message 
          : 'An error occurred' 
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {children}
      
      {errors.general && (
        <div 
          className="text-red-500 text-sm" 
          role="alert"
          aria-live="polite"
        >
          {errors.general}
        </div>
      )}
      
      <Button 
        type="submit" 
        disabled={isSubmitting}
        aria-describedby={errors.general ? 'form-error' : undefined}
      >
        {isSubmitting ? 'Submitting...' : 'Submit'}
      </Button>
    </form>
  )
}
```

### **2. Secure Authentication Components**

```typescript
// components/forms/LoginForm.tsx - Secure authentication
import React from 'react'
import { z } from 'zod'
import { useAuth } from '@/contexts/AuthContext'
import { SecureForm } from './SecureForm'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { userInputSchemas } from '@/lib/validators'

const loginSchema = z.object({
  email: userInputSchemas.email,
  password: z.string().min(1, 'Password is required').max(128)
})

export const LoginForm: React.FC = () => {
  const { login } = useAuth()

  const handleLogin = async (data: z.infer<typeof loginSchema>) => {
    try {
      await login(data.email, data.password)
    } catch (error) {
      // Error handled by SecureForm
      throw error
    }
  }

  return (
    <div className="max-w-md mx-auto p-6 border rounded-lg">
      <h2 className="text-2xl font-bold mb-6 text-center">Sign In</h2>
      
      <SecureForm onSubmit={handleLogin} schema={loginSchema}>
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            name="email"
            required
            autoComplete="email"
            aria-describedby="email-error"
            className="w-full"
          />
        </div>
        
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            name="password"
            required
            autoComplete="current-password"
            aria-describedby="password-error"
            className="w-full"
          />
        </div>
      </SecureForm>
    </div>
  )
}
```

### **3. Web3 Wallet Connection Security**

```typescript
// components/features/wallet/WalletConnect.tsx
import React, { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { connectWallet, Web3SecurityError } from '@/lib/web3-utils'
import { useAuth } from '@/contexts/AuthContext'

export const WalletConnect: React.FC = () => {
  const [isConnecting, setIsConnecting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { loginWithWallet } = useAuth()

  const handleConnect = async () => {
    setIsConnecting(true)
    setError(null)
    
    try {
      // Secure wallet connection with validation
      const { address, chainId, provider } = await connectWallet()
      
      // Generate secure sign-in message
      const nonce = crypto.getRandomValues(new Uint8Array(16))
        .reduce((acc, byte) => acc + byte.toString(16).padStart(2, '0'), '')
      
      const timestamp = new Date().toISOString()
      const message = generateSignInMessage(address, nonce, timestamp)
      
      // Request signature
      const signer = provider.getSigner()
      const signature = await signer.signMessage(message)
      
      // Authenticate with backend
      await loginWithWallet(message, signature)
      
    } catch (error) {
      if (error instanceof Web3SecurityError) {
        setError(error.message)
      } else if (error.code === 4001) {
        setError('Connection cancelled by user')
      } else {
        setError('Failed to connect wallet. Please try again.')
      }
    } finally {
      setIsConnecting(false)
    }
  }

  return (
    <div className="space-y-4">
      <Button
        onClick={handleConnect}
        disabled={isConnecting}
        className="w-full"
        variant="outline"
      >
        {isConnecting ? 'Connecting...' : 'Connect Wallet'}
      </Button>
      
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      
      <p className="text-sm text-muted-foreground text-center">
        By connecting your wallet, you agree to our terms of service.
      </p>
    </div>
  )
}
```

### **4. Secure Comment System**

```typescript
// components/features/comments/CommentForm.tsx
import React, { useState } from 'react'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { apiClient } from '@/lib/api-client'
import { validateAndSanitize } from '@/lib/validators'

const commentSchema = z.object({
  content: z.string()
    .min(1, 'Comment cannot be empty')
    .max(1000, 'Comment too long')
    .transform(content => content.trim())
})

interface CommentFormProps {
  articleId: string
  onCommentAdded: (comment: any) => void
}

export const CommentForm: React.FC<CommentFormProps> = ({ 
  articleId, 
  onCommentAdded 
}) => {
  const [content, setContent] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setError(null)

    try {
      // Validate and sanitize input
      const result = validateAndSanitize({ content }, commentSchema)
      
      if (!result.success) {
        setError(result.error)
        return
      }

      // Submit comment via secure API client
      const comment = await apiClient.post(`/api/articles/${articleId}/comments`, {
        content: result.data.content
      })

      onCommentAdded(comment)
      setContent('')
      
    } catch (error) {
      setError('Failed to post comment. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="Share your thoughts..."
        maxLength={1000}
        rows={4}
        required
        aria-describedby="comment-error"
        className="w-full"
      />
      
      <div className="flex justify-between items-center">
        <span className="text-sm text-muted-foreground">
          {content.length}/1000 characters
        </span>
        
        <Button 
          type="submit" 
          disabled={isSubmitting || !content.trim()}
        >
          {isSubmitting ? 'Posting...' : 'Post Comment'}
        </Button>
      </div>
      
      {error && (
        <div 
          id="comment-error"
          className="text-red-500 text-sm"
          role="alert"
          aria-live="polite"
        >
          {error}
        </div>
      )}
    </form>
  )
}
```

### **5. Secure Search Component**

```typescript
// components/features/search/SearchForm.tsx
import React, { useState, useCallback } from 'react'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { validateAndSanitize } from '@/lib/validators'
import { userInputSchemas } from '@/lib/validators'
import { debounce } from 'lodash'

interface SearchFormProps {
  onSearch: (query: string) => void
  placeholder?: string
}

export const SearchForm: React.FC<SearchFormProps> = ({ 
  onSearch, 
  placeholder = "Search articles..." 
}) => {
  const [query, setQuery] = useState('')
  const [error, setError] = useState<string | null>(null)

  // Debounced search to prevent excessive API calls
  const debouncedSearch = useCallback(
    debounce((searchQuery: string) => {
      if (searchQuery.trim()) {
        // Validate and sanitize search query
        const result = validateAndSanitize(
          { query: searchQuery }, 
          z.object({ query: userInputSchemas.searchQuery })
        )
        
        if (result.success) {
          onSearch(result.data.query)
          setError(null)
        } else {
          setError('Invalid search query')
        }
      }
    }, 300),
    [onSearch]
  )

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setQuery(value)
    
    // Clear error when user starts typing
    if (error) setError(null)
    
    // Trigger debounced search
    debouncedSearch(value)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (query.trim()) {
      // Immediate search on form submit
      const result = validateAndSanitize(
        { query: query.trim() }, 
        z.object({ query: userInputSchemas.searchQuery })
      )
      
      if (result.success) {
        onSearch(result.data.query)
        setError(null)
      } else {
        setError('Invalid search query')
      }
    }
  }

  return (
    <form onSubmit={handleSubmit} className="relative">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
        <Input
          type="search"
          value={query}
          onChange={handleInputChange}
          placeholder={placeholder}
          maxLength={100}
          className="pl-10 pr-4"
          aria-describedby={error ? 'search-error' : undefined}
        />
      </div>
      
      {error && (
        <div 
          id="search-error"
          className="text-red-500 text-sm mt-1"
          role="alert"
          aria-live="polite"
        >
          {error}
        </div>
      )}
    </form>
  )
}
```

---

## 🎨 Layout Components Security

### **Secure Market Ticker** (`layout/MarketTicker.tsx`)

```typescript
import React, { useState, useEffect } from 'react'
import { TrendingUp, TrendingDown } from 'lucide-react'
import { formatPrice, formatPercentage } from '@/lib/ui-utils'

interface CryptoPrice {
  symbol: string
  price: number
  change: number
  isPositive: boolean
}

export const MarketTicker: React.FC = () => {
  const [prices, setPrices] = useState<CryptoPrice[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchPrices = async () => {
      try {
        // Use secure API client for data fetching
        const response = await fetch('/api/market/prices', {
          headers: {
            'X-Requested-With': 'XMLHttpRequest' // CSRF protection
          }
        })
        
        if (!response.ok) {
          throw new Error('Failed to fetch market data')
        }
        
        const data = await response.json()
        
        // Validate and sanitize price data
        const validatedPrices = data
          .filter((item: any) => 
            item.symbol && 
            typeof item.price === 'number' && 
            typeof item.change === 'number'
          )
          .map((item: any) => ({
            symbol: item.symbol.toUpperCase(),
            price: Math.max(0, item.price), // Ensure positive prices
            change: item.change,
            isPositive: item.change >= 0
          }))
        
        setPrices(validatedPrices)
        setError(null)
      } catch (error) {
        setError('Failed to load market data')
        console.error('Market data fetch error:', error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchPrices()
    
    // Refresh every 30 seconds
    const interval = setInterval(fetchPrices, 30000)
    return () => clearInterval(interval)
  }, [])

  if (isLoading) {
    return (
      <div className="bg-muted p-2">
        <div className="animate-pulse flex space-x-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="flex space-x-2">
              <div className="h-4 w-8 bg-muted-foreground/20 rounded"></div>
              <div className="h-4 w-16 bg-muted-foreground/20 rounded"></div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-destructive/10 text-destructive p-2 text-center text-sm">
        {error}
      </div>
    )
  }

  return (
    <div className="bg-muted border-b">
      <div className="container mx-auto px-4">
        <div className="flex overflow-x-auto scrollbar-hide py-2 space-x-6">
          {prices.map((price) => (
            <div 
              key={price.symbol} 
              className="flex items-center space-x-2 min-w-fit"
            >
              <span className="font-semibold text-sm">
                {price.symbol}
              </span>
              <span className="text-sm">
                {formatPrice(price.price)}
              </span>
              <div 
                className={`flex items-center space-x-1 ${
                  price.isPositive ? 'text-green-500' : 'text-red-500'
                }`}
              >
                {price.isPositive ? (
                  <TrendingUp className="w-3 h-3" />
                ) : (
                  <TrendingDown className="w-3 h-3" />
                )}
                <span className="text-xs">
                  {formatPercentage(Math.abs(price.change))}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
```

---

## 🔧 Component Development Guidelines

### **TypeScript Requirements**
```typescript
// Always define strict interfaces for props
interface ComponentProps {
  // Required props
  id: string
  title: string
  
  // Optional props with defaults
  variant?: 'default' | 'outline' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  
  // Event handlers with proper typing
  onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void
  onSubmit?: (data: FormData) => Promise<void>
  
  // Children and className for composition
  children?: React.ReactNode
  className?: string
}

// Use proper generic types for data
interface DataComponentProps<T> {
  data: T[]
  renderItem: (item: T, index: number) => React.ReactNode
  loading?: boolean
  error?: string | null
}
```

### **Error Boundary Pattern**
```typescript
// components/ui/ErrorBoundary.tsx
import React from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'

interface ErrorBoundaryState {
  hasError: boolean
  error?: Error
}

export class ErrorBoundary extends React.Component<
  React.PropsWithChildren<{ fallback?: React.ReactNode }>,
  ErrorBoundaryState
> {
  constructor(props: React.PropsWithChildren<{ fallback?: React.ReactNode }>) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    // Log error to monitoring service (don't expose sensitive details)
    console.error('Component error:', {
      message: error.message,
      stack: error.stack?.substring(0, 500), // Limit stack trace
      componentStack: errorInfo.componentStack?.substring(0, 500)
    })
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <Alert variant="destructive">
          <AlertDescription>
            Something went wrong. Please refresh the page.
          </AlertDescription>
        </Alert>
      )
    }

    return this.props.children
  }
}
```

### **Accessibility Requirements**
```typescript
// Always include proper ARIA attributes
export const AccessibleButton: React.FC<ButtonProps> = ({
  children,
  onClick,
  disabled,
  ariaLabel,
  ariaDescribedBy,
  ...props
}) => {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      aria-describedby={ariaDescribedBy}
      aria-disabled={disabled}
      role="button"
      tabIndex={disabled ? -1 : 0}
      className={cn(
        "focus:outline-none focus:ring-2 focus:ring-primary",
        props.className
      )}
      {...props}
    >
      {children}
    </button>
  )
}
```

### **Performance Optimization Patterns**
```typescript
// Use React.memo for expensive components
export const ExpensiveComponent = React.memo<Props>(({ data, config }) => {
  // Memoize expensive calculations
  const processedData = useMemo(() => {
    return data.map(item => expensiveProcessing(item))
  }, [data])
  
  // Debounce user inputs
  const debouncedSearch = useCallback(
    debounce((query: string) => {
      // Search logic
    }, 300),
    []
  )
  
  return (
    <div>
      {/* Component content */}
    </div>
  )
})

// Custom comparison function for complex props
export const OptimizedComponent = React.memo(
  Component,
  (prevProps, nextProps) => {
    return (
      prevProps.id === nextProps.id &&
      JSON.stringify(prevProps.data) === JSON.stringify(nextProps.data)
    )
  }
)
```

---

## 🧪 Component Testing Requirements

### **Security-Focused Component Tests**
```typescript
// components/__tests__/LoginForm.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LoginForm } from '../forms/LoginForm'

describe('LoginForm Security Tests', () => {
  describe('Input Validation', () => {
    it('should sanitize malicious input', async () => {
      const user = userEvent.setup()
      render(<LoginForm />)
      
      const emailInput = screen.getByLabelText(/email/i)
      const maliciousEmail = '<script>alert("xss")</script>test@example.com'
      
      await user.type(emailInput, maliciousEmail)
      
      // Input should be sanitized
      expect(emailInput.value).not.toContain('<script>')
      expect(emailInput.value).toContain('test@example.com')
    })
    
    it('should validate email format', async () => {
      const user = userEvent.setup()
      render(<LoginForm />)
      
      const emailInput = screen.getByLabelText(/email/i)
      const passwordInput = screen.getByLabelText(/password/i)
      const submitButton = screen.getByRole('button', { name: /sign in/i })
      
      await user.type(emailInput, 'invalid-email')
      await user.type(passwordInput, 'ValidPass123!')
      await user.click(submitButton)
      
      await waitFor(() => {
        expect(screen.getByText(/invalid email/i)).toBeInTheDocument()
      })
    })
  })
  
  describe('XSS Prevention', () => {
    it('should prevent script injection in error messages', async () => {
      // Mock API to return malicious error message
      const mockLogin = jest.fn().mockRejectedValue(
        new Error('<script>alert("xss")</script>Invalid credentials')
      )
      
      render(<LoginForm onLogin={mockLogin} />)
      
      // Submit form to trigger error
      const submitButton = screen.getByRole('button', { name: /sign in/i })
      fireEvent.click(submitButton)
      
      await waitFor(() => {
        const errorElement = screen.getByRole('alert')
        expect(errorElement.textContent).not.toContain('<script>')
      })
    })
  })
})
```

---

## 📋 Component Development Checklist

### **Before Creating Components**
- [ ] Define TypeScript interfaces for all props
- [ ] Plan input validation and sanitization strategy
- [ ] Consider accessibility requirements (ARIA labels, keyboard navigation)
- [ ] Design error handling and loading states
- [ ] Plan performance optimizations (memoization, debouncing)

### **During Development**
- [ ] Implement input validation with Zod schemas
- [ ] Sanitize all user inputs with DOMPurify
- [ ] Add proper error boundaries
- [ ] Include loading and error states
- [ ] Implement proper accessibility attributes
- [ ] Add keyboard navigation support

### **Security Requirements**
- [ ] All user inputs validated and sanitized
- [ ] No direct innerHTML usage
- [ ] Error messages don't expose sensitive information
- [ ] Proper CSRF token handling in forms
- [ ] Secure API client usage for data fetching
- [ ] XSS prevention in dynamic content rendering

### **Testing Requirements**
- [ ] Unit tests with security scenarios
- [ ] Accessibility testing (screen readers, keyboard navigation)
- [ ] Performance testing for expensive components
- [ ] Error boundary testing
- [ ] Input validation edge cases

### **Performance Checklist**
- [ ] React.memo for expensive components
- [ ] useMemo for expensive calculations
- [ ] useCallback for event handlers
- [ ] Debouncing for user inputs
- [ ] Lazy loading for large components
- [ ] Image optimization and loading states

---

## 🚀 Advanced Component Patterns

### **Compound Component Pattern**
```typescript
// components/ui/Card/index.tsx
const Card = ({ children, className, ...props }) => (
  <div className={cn("rounded-lg border bg-card", className)} {...props}>
    {children}
  </div>
)

const CardHeader = ({ children, className, ...props }) => (
  <div className={cn("p-6 pb-0", className)} {...props}>
    {children}
  </div>
)

const CardContent = ({ children, className, ...props }) => (
  <div className={cn("p-6", className)} {...props}>
    {children}
  </div>
)

// Export as compound component
Card.Header = CardHeader
Card.Content = CardContent

export { Card }
```

### **Render Props Pattern for Data Fetching**
```typescript
// components/features/DataFetcher.tsx
interface DataFetcherProps<T> {
  url: string
  children: (props: {
    data: T | null
    loading: boolean
    error: string | null
    refetch: () => void
  }) => React.ReactNode
}

export function DataFetcher<T>({ url, children }: DataFetcherProps<T>) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    
    try {
      const response = await apiClient.get<T>(url)
      setData(response)
    } catch (err) {
      setError('Failed to fetch data')
    } finally {
      setLoading(false)
    }
  }, [url])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return <>{children({ data, loading, error, refetch: fetchData })}</>
}
```

---

## 🎯 Component Success Metrics

### **Security Standards**
- Zero XSS vulnerabilities in component inputs
- All forms use validated schemas
- Proper error boundaries on all async components
- No sensitive data exposed in error messages

### **Performance Standards**
- First Contentful Paint < 2s
- Largest Contentful Paint < 3s
- Cumulative Layout Shift < 0.1
- Time to Interactive < 5s

### **Accessibility Standards**
- WCAG 2.1 AA compliance
- Keyboard navigation support
- Screen reader compatibility
- Proper ARIA attributes

### **Code Quality Standards**
- 100% TypeScript coverage (no `any` types)
- 80%+ test coverage for components
- All components documented with JSDoc
- Consistent design system usage

---

**Remember**: Components are the user interface - they're the first line of defense against attacks and the primary determinant of user experience. Every component must be secure, accessible, and performant.
