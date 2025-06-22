export class NetworkError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'NetworkError';
    this.status = status;
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

interface LogPayload {
  level: 'error' | 'warn' | 'info';
  message: string;
  name: string;
  stack?: string;
  context?: string;
  timestamp: string;
}

/**
 * Log errors in a structured JSON format for easier monitoring.
 * @param error - Error object or unknown failure.
 * @param context - Additional context about where the error occurred.
 */
export const logError = (error: unknown, context?: string): void => {
  const payload: LogPayload = {
    level: 'error',
    message: error instanceof Error ? error.message : String(error),
    name: error instanceof Error ? error.name : 'Error',
    stack: error instanceof Error ? error.stack : undefined,
    context,
    timestamp: new Date().toISOString(),
  };
  console.error(JSON.stringify(payload));
};
