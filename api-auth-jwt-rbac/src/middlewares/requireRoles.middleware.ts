// ============================================
// MIDDLEWARE: RBAC - Require Roles
// ============================================
// 
// Middleware para controle de acesso baseado em roles (RBAC)
// Deve ser usado APÓS o middleware authenticate
// ============================================

import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from '../types';
import { forbiddenResponse } from '../utils/response.util';
import { logAccessDenied } from '../utils/logger.util';

/**
 * Middleware RBAC: Require Roles
 * 
 * Verifica se o usuário autenticado possui uma das roles necessárias.
 * 
 * IMPORTANTE:
 * - Deve ser usado APÓS o middleware authenticate
 * - Requer que req.user esteja definido (via authenticate)
 * - Retorna 403 Forbidden se usuário não tiver a role necessária
 * 
 * @param roles - Roles permitidas (ex: "ADMIN", "MANAGER", "USER")
 * @returns Middleware que retorna 403 se não autorizado
 * 
 * @example
 * // Apenas ADMIN
 * router.get('/admin', authenticate, requireRoles('ADMIN'), controller);
 * 
 * @example
 * // ADMIN ou MANAGER
 * router.get('/admin-or-manager', authenticate, requireRoles('ADMIN', 'MANAGER'), controller);
 * 
 * @example
 * // Múltiplas roles (qualquer uma)
 * router.put('/sensitive', authenticate, requireRoles('ADMIN', 'MANAGER'), controller);
 */
export function requireRoles(...roles: string[]): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authReq = req as AuthRequest;

    // ============================================
    // VERIFICAR SE USUÁRIO ESTÁ AUTENTICADO
    // ============================================
    // Este middleware assume que authenticate já foi executado
    // Se req.user não existir, significa que authenticate não foi chamado antes
    if (!authReq.user) {
      // Este erro não deveria acontecer se usar authenticate antes
      // Mas tratamos para garantir robustez
      forbiddenResponse(res, 'Usuário não autenticado. Use authenticate middleware antes de requireRoles.');
      return;
    }

    // ============================================
    // OBTER ROLES DO USUÁRIO
    // ============================================
    const userRoles = authReq.user.roles || [];

    // Normalizar roles para uppercase para comparação case-insensitive
    const normalizedUserRoles = userRoles.map((r) => r.toUpperCase());
    const normalizedRequiredRoles = roles.map((r) => r.toUpperCase());

    // ============================================
    // VERIFICAR SE USUÁRIO TEM PELO MENOS UMA DAS ROLES NECESSÁRIAS
    // ============================================
    const hasRequiredRole = normalizedRequiredRoles.some((requiredRole) =>
      normalizedUserRoles.includes(requiredRole)
    );

    if (!hasRequiredRole) {
      // ============================================
      // ACESSO NEGADO - LOG E RESPOSTA
      // ============================================
      
      // Log estruturado de acesso negado
      logAccessDenied(
        authReq.user.id,
        authReq.user.username,
        req.path,
        roles.join(', '), // Roles necessárias
        undefined, // Permissão (não usado aqui)
        req.ip
      );

      // Retornar 403 Forbidden com mensagem clara
      forbiddenResponse(
        res,
        `Acesso negado. Roles necessárias: ${roles.join(', ')}. Suas roles: ${userRoles.join(', ') || 'nenhuma'}.`
      );
      return;
    }

    // ============================================
    // ACESSO PERMITIDO - CONTINUAR
    // ============================================
    // Usuário tem pelo menos uma das roles necessárias
    next();
  };
}

/**
 * Helper: Verificar se usuário tem role específica
 * 
 * Útil para lógica condicional dentro de controllers
 * 
 * @param userRoles - Array de roles do usuário
 * @param requiredRole - Role necessária
 * @returns true se usuário tem a role
 */
export function hasRole(userRoles: string[], requiredRole: string): boolean {
  const normalizedUserRoles = userRoles.map((r) => r.toUpperCase());
  return normalizedUserRoles.includes(requiredRole.toUpperCase());
}

/**
 * Helper: Verificar se usuário tem pelo menos uma das roles
 * 
 * @param userRoles - Array de roles do usuário
 * @param requiredRoles - Array de roles necessárias
 * @returns true se usuário tem pelo menos uma das roles
 */
export function hasAnyRole(userRoles: string[], requiredRoles: string[]): boolean {
  const normalizedUserRoles = userRoles.map((r) => r.toUpperCase());
  const normalizedRequiredRoles = requiredRoles.map((r) => r.toUpperCase());
  
  return normalizedRequiredRoles.some((requiredRole) =>
    normalizedUserRoles.includes(requiredRole)
  );
}

/**
 * Helper: Verificar se usuário tem todas as roles
 * 
 * @param userRoles - Array de roles do usuário
 * @param requiredRoles - Array de roles necessárias
 * @returns true se usuário tem todas as roles
 */
export function hasAllRoles(userRoles: string[], requiredRoles: string[]): boolean {
  const normalizedUserRoles = userRoles.map((r) => r.toUpperCase());
  const normalizedRequiredRoles = requiredRoles.map((r) => r.toUpperCase());
  
  return normalizedRequiredRoles.every((requiredRole) =>
    normalizedUserRoles.includes(requiredRole)
  );
}
