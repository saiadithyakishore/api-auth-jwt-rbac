// ============================================
// MIDDLEWARE: Autenticação e Autorização
// ============================================

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { verifyAccessToken, extractTokenFromHeader } from '../utils/jwt-advanced.util';
import * as userRepository from '../repositories/user.repository';
import { AppError, AuthRequest, JWTPayload } from '../types';
import { unauthorizedResponse, forbiddenResponse } from '../utils/response.util';
import { logAccessDenied, logger } from '../utils/logger.util';
import { tokenBlacklist } from '../services/token-blacklist.service';

/**
 * Middleware de autenticação
 * Verifica se o usuário está autenticado através do token JWT
 */
/**
 * Middleware de autenticação (ENTERPRISE)
 * 
 * Verifica JWT token e carrega dados do usuário
 * 
 * Fluxo:
 * 1. Extrai token do header Authorization
 * 2. Verifica token (secret, issuer, audience, expiração)
 * 3. Busca usuário no banco
 * 4. Verifica se usuário está ativo
 * 5. Adiciona dados do usuário ao request
 */
export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // ============================================
    // 1. EXTRAIR TOKEN DO HEADER
    // ============================================
    
    // Express converte headers para lowercase, mas vamos garantir
    const authHeader = req.headers.authorization || 
                      req.headers['authorization'] || 
                      (req.headers as any)['Authorization'];
    
    if (!authHeader) {
      logger.warn('Tentativa de acesso sem token', {
        path: req.path,
        method: req.method,
        ip: req.ip,
      });
      unauthorizedResponse(res, 'Token não fornecido. Envie no header: Authorization: Bearer <token>');
      return;
    }

    // Extrair token do header
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      // Log detalhado para debug
      logger.warn('Formato de token inválido', {
        path: req.path,
        method: req.method,
        headerLength: authHeader.length,
        headerPreview: authHeader.substring(0, 50) + '...',
        ip: req.ip,
      });
      unauthorizedResponse(res, 'Formato de token inválido. Use: Authorization: Bearer <token>');
      return;
    }

    // Log do token extraído (apenas preview em desenvolvimento)
    if (process.env.NODE_ENV !== 'production') {
      logger.debug('Token extraído do header', {
        tokenLength: token.length,
        tokenPreview: token.substring(0, 30) + '...',
        path: req.path,
      });
    }

    // ============================================
    // 2. VERIFICAR TOKEN JWT
    // ============================================
    
    // Checar blacklist antes de validar para evitar usar tokens revogados
    if (tokenBlacklist.isBlacklisted(token)) {
      logger.warn('Tentativa de acesso com token revogado', {
        path: req.path,
        method: req.method,
        ip: req.ip,
      });
      unauthorizedResponse(res, 'Token revogado. Faça login novamente.');
      return;
    }

    let decoded: JWTPayload;
    try {
      // LOG ANTES DA VALIDAÇÃO (desenvolvimento)
      if (process.env.NODE_ENV !== 'production') {
        logger.debug('Iniciando validação do token', {
          tokenLength: token.length,
          path: req.path,
        });
      }

      // Verificar token (usa jwtConfig centralizado)
      decoded = verifyAccessToken(token);

      // LOG APÓS VALIDAÇÃO BEM-SUCEDIDA (desenvolvimento)
      if (process.env.NODE_ENV !== 'production') {
        logger.debug('Token validado com sucesso', {
          userId: decoded.userId,
          username: decoded.username,
          roles: decoded.roles,
          path: req.path,
        });
      }
    } catch (error: any) {
      // LOG DETALHADO DO ERRO (sempre, para debug)
      const errorDetails: any = {
        path: req.path,
        method: req.method,
        errorMessage: error.message,
        errorName: error.name,
        ip: req.ip,
      };

      // Adicionar detalhes específicos do erro JWT
      if (error instanceof jwt.TokenExpiredError) {
        errorDetails.expiredAt = error.expiredAt;
        errorDetails.currentTime = new Date();
      }

      if (error instanceof jwt.JsonWebTokenError) {
        errorDetails.jwtError = error.message;
      }

      logger.warn('Falha na validação do token', errorDetails);

      // Retornar mensagem específica do erro
      if (error instanceof AppError) {
        unauthorizedResponse(res, error.message);
      } else {
        unauthorizedResponse(res, `Token inválido: ${error.message || 'Erro desconhecido'}`);
      }
      return;
    }

        // ============================================
        // 4. BUSCAR USUÁRIO NO BANCO
        // ============================================
    
    const user = await userRepository.findByUsernameWithRolesAndPermissions(
      decoded.username
    );

    if (!user) {
      logger.warn('Usuário não encontrado após validação do token', {
        username: decoded.username,
        userId: decoded.userId,
        path: req.path,
        ip: req.ip,
      });
      unauthorizedResponse(res, 'Usuário não encontrado');
      return;
    }

        // ============================================
        // 5. VERIFICAR SE USUÁRIO ESTÁ ATIVO
        // ============================================
    
    const isActiveValue = user.is_active as unknown as boolean | number;
    const isActive = isActiveValue === 1 || isActiveValue === true;
    if (!isActive) {
      logger.warn('Tentativa de acesso com usuário inativo', {
        userId: user.id,
        username: user.username,
        path: req.path,
        ip: req.ip,
      });
      forbiddenResponse(res, 'Usuário inativo');
      return;
    }

        // ============================================
        // 6. ADICIONAR DADOS DO USUÁRIO AO REQUEST
        // ============================================
    
    const dbRoles = user.roles.map((r) => r.name);
    const permissions = user.permissions.map((p) => p.name);

    // Roles e permissions usados no token permanecem os do payload
    (req as AuthRequest).user = {
      id: user.id,
      username: user.username,
      email: user.email,
      roles: decoded.roles, // roles do token validado
      permissions,
      dbRoles, // roles atuais no banco (para decisões de autorização adicionais)
    };

    // Log de sucesso (apenas em desenvolvimento)
    if (process.env.NODE_ENV !== 'production') {
      logger.debug('Autenticação bem-sucedida', {
        userId: user.id,
        username: user.username,
        roles: user.roles.map((r) => r.name),
        path: req.path,
      });
    }

    next();
  } catch (error: any) {
    // Erro inesperado - log completo
    logger.error('Erro inesperado no middleware de autenticação', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      ip: req.ip,
    });

    unauthorizedResponse(res, 'Erro ao processar autenticação');
  }
}

/**
 * Middleware de autorização por role (ENTERPRISE)
 * 
 * Verifica se o usuário possui uma das roles necessárias.
 * Middleware reutilizável e desacoplado.
 * 
 * @param allowedRoles - Roles permitidas (ex: "ADMIN", "MANAGER")
 * @returns Middleware que retorna 401 se não autenticado, 403 se sem permissão
 * 
 * @example
 * router.put('/admin-only', authenticate, authorizeRoles('ADMIN'), handler);
 * router.get('/admin-or-manager', authenticate, authorizeRoles('ADMIN', 'MANAGER'), handler);
 */
export function authorizeRoles(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authReq = req as AuthRequest;

    // Verificar autenticação
    if (!authReq.user) {
      unauthorizedResponse(res, 'Não autenticado. Token necessário.');
      return;
    }

    const userRoles = authReq.user.roles;

    // Verificar se o usuário possui pelo menos uma das roles permitidas
    const hasRole = allowedRoles.some((role) =>
      userRoles.includes(role.toUpperCase())
    );

    if (!hasRole) {
      // Log de acesso negado
      logAccessDenied(
        authReq.user.id,
        authReq.user.username,
        req.path,
        allowedRoles.join(', '),
        undefined,
        req.ip
      );

      forbiddenResponse(
        res,
        `Acesso negado. Roles necessárias: ${allowedRoles.join(', ')}. Roles do usuário: ${userRoles.join(', ')}.`
      );
      return;
    }

    next();
  };
}

/**
 * Middleware de autorização por permissão
 * Verifica se o usuário possui a permissão necessária
 */
export function authorizePermission(requiredPermission: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authReq = req as AuthRequest;

    if (!authReq.user) {
      res.status(401).json({
        success: false,
        message: 'Usuário não autenticado',
      });
      return;
    }

    const userPermissions = authReq.user.permissions;

    // Verificar se o usuário possui a permissão necessária
    if (!userPermissions.includes(requiredPermission)) {
      res.status(403).json({
        success: false,
        message: `Acesso negado. Permissão '${requiredPermission}' necessária.`,
      });
      return;
    }

    next();
  };
}

/**
 * Middleware combinado: autenticação + autorização por role
 */
export function requireAuthAndRole(...allowedRoles: string[]) {
  return [
    authenticate,
    authorizeRoles(...allowedRoles),
  ];
}

/**
 * Middleware combinado: autenticação + autorização por permissão
 */
export function requireAuthAndPermission(requiredPermission: string) {
  return [
    authenticate,
    authorizePermission(requiredPermission),
  ];
}
