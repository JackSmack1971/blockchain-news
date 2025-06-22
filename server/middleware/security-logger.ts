import { Request } from 'express';
import { createLogger, transports, format } from 'winston';
import { recordSecurityEvent } from '../monitoring/metrics';

export const securityLogger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [
    new transports.File({ filename: 'logs/security.log' }),
    new transports.Console({ level: 'warn' }),
  ],
});

export interface SecurityDetails {
  event: string;
  details?: unknown;
}

/**
 * Log a security related event and update metrics.
 * @param event event name
 * @param details additional context
 * @param req originating request
 */
export function logSecurityEvent(
  event: string,
  details: unknown,
  req: Request,
): void {
  recordSecurityEvent(event, 'high');
  securityLogger.warn('SECURITY_EVENT', {
    event,
    details,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString(),
    sessionId: req.sessionID,
    userId: req.session?.user?.id,
  });
}
