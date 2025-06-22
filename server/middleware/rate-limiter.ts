import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { logSecurityEvent } from './security-logger';
import { rateLimitHits } from '../monitoring/metrics';

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req: Request, res: Response, _next: NextFunction): void {
    rateLimitHits.inc({ endpoint: req.path });
    logSecurityEvent(
      'RATE_LIMIT_EXCEEDED',
      { endpoint: req.path, method: req.method },
      req,
    );
    res.status(429).json({ error: 'Too many login attempts, please try again later' });
  },
});
