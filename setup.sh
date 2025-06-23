#!/bin/bash
set -e

echo "🚀 Setting up BlockchainNews development environment for Codex..."

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to compare versions
version_ge() {
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

# Check Node.js version
echo "📋 Checking Node.js version..."
if command_exists node; then
    node_version=$(node -v | sed 's/v//')
    if version_ge "18.0.0" "$node_version"; then
        echo "❌ Node.js 18.0.0 or higher required. Current: $node_version"
        echo "Please install Node.js 18+ or use a version manager like nvm"
        exit 1
    fi
    echo "✅ Node.js version check passed: $node_version"
else
    echo "❌ Node.js not found. Please install Node.js 18+"
    exit 1
fi

# Check/Install pnpm
echo "📦 Checking pnpm..."
if ! command_exists pnpm; then
    echo "Installing pnpm..."
    npm install -g pnpm
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install pnpm"
        exit 1
    fi
fi
echo "✅ pnpm available: $(pnpm --version)"

# Install project dependencies
echo "📦 Installing project dependencies..."
if [ -f "package.json" ]; then
    pnpm install
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        echo "Trying with npm as fallback..."
        npm install
    fi
    echo "✅ Dependencies installed successfully"
else
    echo "❌ package.json not found. Are you in the project root?"
    exit 1
fi

# Setup environment variables
echo "⚙️ Setting up environment variables..."
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cat > .env << 'EOL'
NODE_ENV=development
PORT=3001
SESSION_SECRET=codex-development-secret-key-minimum-32-characters-long-for-security
DATABASE_URL=postgresql://codex:password@localhost:5432/blockchain_news_dev
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
LOG_LEVEL=info
FRONTEND_URL=http://localhost:3000
COOKIE_SECURE=false
COOKIE_MAX_AGE=86400000
COOKIE_DOMAIN=localhost
EOL
    echo "✅ Environment file created"
else
    echo "✅ Environment file already exists"
fi

# Check PostgreSQL availability
echo "🗄️ Checking database setup..."
if command_exists psql; then
    # Try to connect to default PostgreSQL
    if psql -h localhost -U postgres -c '\l' >/dev/null 2>&1; then
        echo "✅ PostgreSQL connection available"
        
        # Try to create development database
        createdb blockchain_news_dev 2>/dev/null && echo "✅ Development database created" || echo "ℹ️ Development database may already exist"
    else
        echo "⚠️ PostgreSQL available but connection failed"
        echo "   You may need to configure authentication or start the service"
    fi
else
    echo "⚠️ PostgreSQL not found"
    echo "   Database operations will be skipped in development"
    echo "   Install PostgreSQL if database functionality is needed"
fi

# Validate environment configuration
echo "🔍 Validating environment configuration..."
if [ -f "server/config/environment.ts" ]; then
    # Create a simple validation script
    cat > validate-env.js << 'EOL'
const fs = require('fs');
const path = require('path');

// Simple environment validation
const requiredVars = [
    'SESSION_SECRET',
    'PORT',
    'NODE_ENV'
];

// Load .env file
if (fs.existsSync('.env')) {
    const envContent = fs.readFileSync('.env', 'utf8');
    const envVars = {};
    
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            envVars[key.trim()] = value.trim();
        }
    });
    
    let allValid = true;
    
    requiredVars.forEach(varName => {
        if (!envVars[varName]) {
            console.log(`❌ Missing required environment variable: ${varName}`);
            allValid = false;
        } else if (varName === 'SESSION_SECRET' && envVars[varName].length < 32) {
            console.log(`❌ SESSION_SECRET must be at least 32 characters long`);
            allValid = false;
        } else {
            console.log(`✅ ${varName}: Configured`);
        }
    });
    
    if (allValid) {
        console.log('✅ Environment validation passed');
    } else {
        console.log('❌ Environment validation failed');
        process.exit(1);
    }
} else {
    console.log('❌ .env file not found');
    process.exit(1);
}
EOL

    node validate-env.js
    rm validate-env.js
else
    echo "⚠️ Environment validation skipped (config file not found)"
fi

# Build project
echo "🏗️ Building project..."
if npm run build >/dev/null 2>&1; then
    echo "✅ Build successful"
else
    echo "⚠️ Build failed or no build script found"
    echo "   This may be normal for development-only setup"
fi

# Run tests to verify setup
echo "🧪 Running quick test verification..."
if npm test >/dev/null 2>&1 || pnpm test >/dev/null 2>&1; then
    echo "✅ Tests pass"
else
    echo "⚠️ Some tests failed or no test script found"
    echo "   This may be normal during initial setup"
fi

# Security audit
echo "🔒 Running security audit..."
if pnpm audit --audit-level high >/dev/null 2>&1; then
    echo "✅ No high-severity vulnerabilities found"
else
    echo "⚠️ Security audit found issues - review recommended"
    echo "   Run 'pnpm audit' for details"
fi

# Final summary
echo ""
echo "🎉 BlockchainNews Codex environment setup complete!"
echo ""
echo "📊 Environment Summary:"
echo "   Node.js: $(node -v)"
echo "   Package Manager: pnpm $(pnpm --version)"
echo "   Project Dependencies: Installed"
echo "   Environment Variables: Configured"
echo "   Database: $(command_exists psql && echo "PostgreSQL available" || echo "Not configured")"
echo ""
echo "🚀 Getting Started:"
echo "   Start Development Server: pnpm run dev"
echo "   Start Backend Server: pnpm run server:dev"
echo "   Run Tests: pnpm test"
echo "   Security Tests: pnpm run test:security"
echo ""
echo "📚 Documentation:"
echo "   Main Guide: AGENTS.md"
echo "   Frontend Guide: src/lib/AGENTS.md"
echo "   Backend Guide: server/AGENTS.md"
echo "   Testing Guide: server/__tests__/AGENTS.md"
echo ""
echo "🔧 Troubleshooting:"
echo "   Type Errors: pnpm run type-check"
echo "   Lint Issues: pnpm run lint"
echo "   Build Issues: pnpm run build"
echo "   Dependencies: rm -rf node_modules && pnpm install"
echo ""
echo "✨ Codex is ready for BlockchainNews development!"
echo "   Focus areas: Security-first, Web3 integration, Performance optimization"
