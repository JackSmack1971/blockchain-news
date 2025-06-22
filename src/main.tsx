import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ErrorBoundary } from './components/ErrorBoundary.tsx'
import './index.css'
import App from './App.tsx'

// Development debugging
console.log('🚀 Starting BlockchainNews application...');

// Check if root element exists
const rootElement = document.getElementById('root');
if (!rootElement) {
  console.error('❌ Root element not found!');
  document.body.innerHTML = `
    <div style="padding: 20px; text-align: center; font-family: system-ui;">
      <h1 style="color: red;">Error: Root element not found</h1>
      <p>The application could not initialize because the root element is missing.</p>
    </div>
  `;
  throw new Error('Root element not found');
}

console.log('✅ Root element found, initializing React...');

try {
  const root = createRoot(rootElement);
  
  root.render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>
  );
  
  console.log('✅ React application rendered successfully!');
  
  // Additional development info
  console.log('📊 Application Info:', {
    NODE_ENV: import.meta.env.MODE,
    DEV: import.meta.env.DEV,
    PROD: import.meta.env.PROD,
    BASE_URL: import.meta.env.BASE_URL
  });
  
} catch (error) {
  console.error('❌ Failed to render React application:', error);
  
  // Fallback error display
  document.body.innerHTML = `
    <div style="padding: 20px; text-align: center; font-family: system-ui;">
      <h1 style="color: red;">Application Error</h1>
      <p>The React application failed to initialize.</p>
      <details style="margin-top: 20px; text-align: left;">
        <summary>Error Details</summary>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow: auto;">
${error instanceof Error ? `${error.message}\n\n${error.stack}` : String(error)}
        </pre>
      </details>
    </div>
  `;
}
