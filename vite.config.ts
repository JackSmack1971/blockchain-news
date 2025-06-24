import path from 'path'
import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import type { Request, Response, NextFunction } from 'express'
import { securityMiddleware } from './server/middleware/security'

export function securityPlugin(): Plugin {
  return {
    name: 'security-middleware',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        securityMiddleware(
          req as unknown as Request,
          res as unknown as Response,
          next as NextFunction,
        )
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), securityPlugin()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})

