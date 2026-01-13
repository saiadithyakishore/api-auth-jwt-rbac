// ============================================
// UTILITÁRIO: JWT Avançado (Access + Refresh Token)
// ============================================
// 
// Implementação enterprise de JWT com:
// - Access Token (curto, para requisições)
// - Refresh Token (longo, para renovação)
// - Rotação de tokens
// ============================================

import jwt, { SignOptions, Secret } from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { StringValue } from 'ms';
import { JWTPayload, AppError } from '../types';
import jwtConfig from '../config/jwt.config';
import { logger } from './logger.util';

// ============================================
// ACCESS TOKEN (Curto - 15 minutos)
// ============================================

/**
 * Gera Access Token (curto, para requisições)
 * 
 * Boas práticas:
 * - Tempo curto (15min) reduz impacto se token for comprometido
 * - Contém apenas dados essenciais
 * - Renovado via Refresh Token
 */
/**
 * Gera Access Token (curto, para requisições)
 * 
 * IMPORTANTE: Usa configuração centralizada para garantir consistência
 */
export function generateAccessToken(payload: JWTPayload): string {
  try {
    // Garantir que secret é string (não undefined)
    const secret: Secret = jwtConfig.secret;
    if (!secret || typeof secret !== 'string') {
      throw new AppError('JWT_SECRET não configurado', 500);
    }

    // Tipar explicitamente as opções para evitar conflito de overload
    // expiresIn aceita StringValue (do pacote 'ms') ou number
    const signOptions: SignOptions = {
      expiresIn: jwtConfig.accessExpiresIn as StringValue,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
      algorithm: jwtConfig.algorithm,
      jwtid: randomUUID(),
    };

    const token = jwt.sign(payload, secret, signOptions);

    // Log em desenvolvimento para debug
    if (process.env.NODE_ENV !== 'production') {
      logger.debug('Access token gerado', {
        userId: payload.userId,
        username: payload.username,
        roles: payload.roles,
        expiresIn: jwtConfig.accessExpiresIn,
      });
    }

    return token;
  } catch (error) {
    logger.error('Erro ao gerar access token', { error, payload: { userId: payload.userId } });
    throw new AppError('Erro ao gerar token de acesso', 500);
  }
}

/**
 * Verifica Access Token
 * 
 * IMPORTANTE: Usa EXATAMENTE as mesmas configurações da geração
 * (secret, issuer, audience, algorithm)
 */
export function verifyAccessToken(token: string): JWTPayload {
  try {
    // Garantir que secret é string (não undefined)
    const secret: Secret = jwtConfig.secret;
    if (!secret || typeof secret !== 'string') {
      throw new AppError('JWT_SECRET não configurado', 500);
    }

    // Verificar token com TODAS as opções (garante consistência)
    const decoded = jwt.verify(token, secret, {
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
      algorithms: [jwtConfig.algorithm],
    }) as JWTPayload;

    // Log em desenvolvimento
    if (process.env.NODE_ENV !== 'production') {
      logger.debug('Access token verificado com sucesso', {
        userId: decoded.userId,
        username: decoded.username,
      });
    }

    return decoded;
  } catch (error) {
    // Log detalhado do erro para debug
    if (error instanceof jwt.TokenExpiredError) {
      logger.warn('Token expirado', {
        expiredAt: error.expiredAt,
        currentTime: new Date(),
      });
      throw new AppError('Access token expirado. Use refresh token para renovar.', 401);
    }
    
    if (error instanceof jwt.JsonWebTokenError) {
      logger.warn('Token inválido', {
        error: error.message,
        name: error.name,
      });
      throw new AppError(`Token inválido: ${error.message}`, 401);
    }

    // Erro inesperado
    logger.error('Erro ao verificar access token', { error });
    throw new AppError('Erro ao verificar access token', 401);
  }
}

// ============================================
// REFRESH TOKEN (Longo - 7 dias)
// ============================================

/**
 * Gera Refresh Token (longo, para renovação)
 * 
 * Boas práticas:
 * - Tempo longo (7 dias) para conveniência do usuário
 * - Deve ser armazenado de forma segura (httpOnly cookie em produção)
 * - Usado apenas para renovar access token
 */
export function generateRefreshToken(payload: { userId: number; username: string }): string {
  // Garantir que refreshSecret é string (não undefined)
  const refreshSecret: Secret = jwtConfig.refreshSecret;
  if (!refreshSecret || typeof refreshSecret !== 'string') {
    throw new AppError('JWT_REFRESH_SECRET não configurado', 500);
  }

  // Tipar explicitamente as opções para evitar conflito de overload
  // expiresIn aceita StringValue (do pacote 'ms') ou number
  const signOptions: SignOptions = {
    expiresIn: jwtConfig.refreshExpiresIn as StringValue,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    algorithm: jwtConfig.algorithm,
    jwtid: randomUUID(),
  };

  return jwt.sign(
    {
      userId: payload.userId,
      username: payload.username,
      type: 'refresh',
    },
    refreshSecret,
    signOptions
  );
}

/**
 * Verifica Refresh Token
 */
export function verifyRefreshToken(token: string): { userId: number; username: string } {
  try {
    // Garantir que refreshSecret é string (não undefined)
    const refreshSecret: Secret = jwtConfig.refreshSecret;
    if (!refreshSecret || typeof refreshSecret !== 'string') {
      throw new AppError('JWT_REFRESH_SECRET não configurado', 500);
    }

    const decoded = jwt.verify(token, refreshSecret, {
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
      algorithms: [jwtConfig.algorithm],
    }) as any;

    if (decoded.type !== 'refresh') {
      throw new AppError('Token não é um refresh token válido', 401);
    }

    return {
      userId: decoded.userId,
      username: decoded.username,
    };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new AppError('Refresh token expirado. Faça login novamente.', 401);
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new AppError('Refresh token inválido', 401);
    }
    throw error;
  }
}

// ============================================
// TOKEN PAIR (Access + Refresh)
// ============================================

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/**
 * Gera par de tokens (Access + Refresh)
 */
export function generateTokenPair(payload: JWTPayload): TokenPair {
  return {
    accessToken: generateAccessToken(payload),
    refreshToken: generateRefreshToken({
      userId: payload.userId,
      username: payload.username,
    }),
  };
}

// ============================================
// COMPATIBILIDADE COM CÓDIGO ANTIGO
// ============================================

/**
 * @deprecated Use generateAccessToken em vez disso
 * Mantido para compatibilidade
 */
export function generateToken(payload: JWTPayload): string {
  return generateAccessToken(payload);
}

/**
 * @deprecated Use verifyAccessToken em vez disso
 * Mantido para compatibilidade
 */
export function verifyToken(token: string): JWTPayload {
  return verifyAccessToken(token);
}

// ============================================
// EXTRAÇÃO DE TOKEN DO HEADER
// ============================================

/**
 * Extrai o token do header Authorization
 * 
 * IMPORTANTE: Trata vários formatos possíveis:
 * - "Bearer TOKEN"
 * - "bearer TOKEN" (case-insensitive)
 * - "TOKEN" (sem Bearer, para compatibilidade)
 * 
 * @param authHeader - Header Authorization
 * @returns Token extraído ou null
 */
export function extractTokenFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader) {
    return null;
  }

  // Remover espaços extras, quebras de linha e caracteres invisíveis
  const cleanHeader = authHeader.trim().replace(/\s+/g, ' ').replace(/[\r\n\t]/g, '');

  // Dividir por espaço
  const parts = cleanHeader.split(' ');

  // Caso 1: "Bearer TOKEN" ou "bearer TOKEN" (case-insensitive)
  if (parts.length >= 2 && parts[0].toLowerCase() === 'bearer') {
    // Juntar todas as partes após "Bearer" (caso token tenha espaços internos - não deveria, mas tratamos)
    const token = parts.slice(1).join(' ').trim();
    return token.length > 0 ? token : null;
  }

  // Caso 2: Apenas o token (sem Bearer) - para compatibilidade
  if (parts.length === 1 && parts[0].length > 0) {
    return parts[0].trim();
  }

  // Formato inválido
  return null;
}
