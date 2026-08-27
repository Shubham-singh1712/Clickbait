type LogLevel = 'info' | 'warn' | 'error' | 'debug';

class Logger {
  private sanitize(message: string | object): string {
    let str = typeof message === 'object' ? JSON.stringify(message) : String(message);

    // Redact private keys, tokens, and sensitive headers
    str = str.replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi, '[REDACTED_PRIVATE_KEY]');
    str = str.replace(/"?(?:privateKey|secret|password|token|apiKey)"?\s*[:=]\s*"?([^",\s}]+)"?/gi, '"$1":"[REDACTED]"');

    return str;
  }

  private format(level: LogLevel, message: string | object, context?: string): string {
    const timestamp = new Date().toISOString();
    const tag = context ? `[${context}]` : '';
    const cleanMessage = this.sanitize(message);
    return `[${timestamp}] [${level.toUpperCase()}] ${tag} ${cleanMessage}`;
  }

  public info(message: string | object, context?: string): void {
    console.log(this.format('info', message, context));
  }

  public warn(message: string | object, context?: string): void {
    console.warn(this.format('warn', message, context));
  }

  public error(message: string | object, error?: Error | unknown, context?: string): void {
    const errorDetails = error instanceof Error ? `\nStack: ${error.stack}` : '';
    console.error(`${this.format('error', message, context)}${errorDetails}`);
  }

  public debug(message: string | object, context?: string): void {
    if (process.env.NODE_ENV !== 'production') {
      console.debug(this.format('debug', message, context));
    }
  }
}

export const logger = new Logger();
