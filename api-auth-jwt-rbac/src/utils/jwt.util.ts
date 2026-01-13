// ============================================
// UTILITÁRIO: JWT (JSON Web Token)
// ============================================

import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { JWTPayload, AppError } from '../types';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_change_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Validar JWT_SECRET em produção
if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'default_secret_change_in_production')) {
  throw new Error('JWT_SECRET deve ser configurado em produção!');
}

/**
 * Gera um token JWT para o usuário
 * @param payload - Dados do usuário a serem incluídos no token
 * @returns Token JWT assinado
 */
export function generateToken(payload: JWTPayload): string {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

/**
 * Verifica e decodifica um token JWT
 * @param token - Token JWT a ser verificado
 * @returns Payload decodificado do token
 * @throws Erro se o token for inválido ou expirado
 */
export function verifyToken(token: string): JWTPayload {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new AppError('Token expirado', 401);
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new AppError('Token inválido', 401);
    }
    throw new AppError('Erro ao verificar token', 401);
  }
}

/**
 * Extrai o token do header Authorization
 * @deprecated Use extractTokenFromHeader de jwt-advanced.util.ts
 * Mantido para compatibilidade
 */
export function extractTokenFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1];
}
