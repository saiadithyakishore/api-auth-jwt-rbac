// ============================================
// UTILITÁRIO: Logs Estruturados (Winston)
// ============================================
// 
// Sistema de logging profissional para produção
// Logs estruturados facilitam análise e debugging
// ============================================

import winston from 'winston';
import path from 'path';

const isTestEnv = process.env.NODE_ENV === 'test';

// Configuração de formatos
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Formato para console (mais legível em desenvolvimento)
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  })
);

const baseTransports = [
  new winston.transports.File({
    filename: path.join('logs', 'error.log'),
    level: 'error',
    maxsize: 5242880, // 5MB
    maxFiles: 5,
    silent: isTestEnv,
  }),
  new winston.transports.File({
    filename: path.join('logs', 'combined.log'),
    maxsize: 5242880, // 5MB
    maxFiles: 5,
    silent: isTestEnv,
  }),
];

// Criar logger
export const logger = winston.createLogger({
  level: isTestEnv ? 'error' : process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'api-auth-rbac' },
  transports: baseTransports,
  silent: isTestEnv,
});

// Em desenvolvimento, também logar no console
if (!isTestEnv && process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: consoleFormat,
    })
  );
}

// ============================================
// HELPERS ESPECÍFICOS PARA O DOMÍNIO
// ============================================

/**
 * Log de tentativa de autenticação
 */
export function logAuthAttempt(
  username: string,
  success: boolean,
  ipAddress?: string,
  reason?: string
): void {
  logger.info('Auth attempt', {
    username,
    success,
    ipAddress,
    reason,
    type: 'AUTH',
  });
}

/**
 * Log de acesso negado
 */
export function logAccessDenied(
  userId: number,
  username: string,
  resource: string,
  requiredRole?: string,
  requiredPermission?: string,
  ipAddress?: string
): void {
  logger.warn('Access denied', {
    userId,
    username,
    resource,
    requiredRole,
    requiredPermission,
    ipAddress,
    type: 'AUTHORIZATION',
  });
}

/**
 * Log de criação de usuário
 */
export function logUserCreated(
  createdBy: number,
  newUserId: number,
  username: string,
  ipAddress?: string
): void {
  logger.info('User created', {
    createdBy,
    newUserId,
    username,
    ipAddress,
    type: 'USER_MANAGEMENT',
  });
}

/**
 * Log de alteração de roles
 */
export function logRoleChange(
  changedBy: number,
  targetUserId: number,
  oldRoles: string[],
  newRoles: string[],
  ipAddress?: string
): void {
  logger.info('Roles changed', {
    changedBy,
    targetUserId,
    oldRoles,
    newRoles,
    ipAddress,
    type: 'RBAC',
  });
}

/**
 * Log de erro crítico
 */
export function logError(
  error: Error,
  context?: Record<string, any>
): void {
  logger.error('Error occurred', {
    message: error.message,
    stack: error.stack,
    ...context,
    type: 'ERROR',
  });
}
