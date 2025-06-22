import { Counter, register } from 'prom-client';

export const securityEvents = new Counter({
  name: 'security_events_total',
  help: 'Total number of security events',
  labelNames: ['event_type', 'severity'],
});

export const failedLogins = new Counter({
  name: 'failed_logins_total',
  help: 'Total number of failed login attempts',
  labelNames: ['reason'],
});

export const rateLimitHits = new Counter({
  name: 'rate_limit_hits_total',
  help: 'Total number of rate limit violations',
  labelNames: ['endpoint'],
});

export function recordSecurityEvent(type: string, severity = 'medium'): void {
  securityEvents.inc({ event_type: type, severity });
}

export function recordFailedLogin(reason: string): void {
  failedLogins.inc({ reason });
}

export { register };
