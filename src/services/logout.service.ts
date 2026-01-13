// ============================================
// SERVICE: Logout (ENTERPRISE)
// ============================================
// 
// Lógica de negócio para logout
// Revoga tokens (access e refresh)
// ============================================

import { tokenBlacklist } from './token-blacklist.service';
import * as refreshTokenRepository from '../repositories/refresh-token.repository';
import { verifyAccessToken } from '../utils/jwt-advanced.util';
import { AppError } from '../types';
import { logger } from '../utils/logger.util';
import jwt from 'jsonwebtoken';

/**
 * Realiza logout do usuário
 * 
 * AÇÕES:
 * 1. Adiciona access token à blacklist
 * 2. Revoga refresh token no banco (se fornecido)
 * 3. Opcional: revoga todos os tokens do usuário
 * 
 * @param accessToken - Access token do header Authorization
 * @param refreshToken - Refresh token (opcional)
 * @param revokeAll - Se true, revoga todos os tokens do usuário
 * @returns void
 */
export async function logout(
  accessToken: string,
  refreshToken?: string,
  revokeAll: boolean = false
): Promise<void> {
  try {
    // ============================================
    // 1. DECODIFICAR ACCESS TOKEN (sem verificar expiração)
    // ============================================
    let decoded: any;
    try {
      // Tentar verificar normalmente
      decoded = verifyAccessToken(accessToken);
    } catch (error: any) {
      // Se token expirado, decodificar sem verificar para obter userId
      if (error.message?.includes('expirado') || error.message?.includes('expired')) {
        decoded = jwt.decode(accessToken) as any;
        if (!decoded || !decoded.exp) {
          throw new AppError('Token inválido', 401);
        }
      } else {
        throw error;
      }
    }

    const userId = decoded?.userId;
    const expiresAt = decoded?.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 15 * 60 * 1000); // Default 15 min

    // ============================================
    // 2. ADICIONAR ACCESS TOKEN À BLACKLIST
    // ============================================
    tokenBlacklist.add(accessToken, expiresAt, userId, 'logout');

    // ============================================
    // 3. REVOGAR REFRESH TOKEN (se fornecido)
    // ============================================
    if (refreshToken) {
      try {
        // Buscar token pelo hash e revogar
        const tokenRecord = await refreshTokenRepository.findByToken(refreshToken);
        if (tokenRecord) {
          await refreshTokenRepository.revoke(tokenRecord.tokenHash);
        }
      } catch (error: any) {
        // Não falhar se refresh token não existir ou já foi revogado
        logger.warn('Erro ao revogar refresh token no logout', {
          error: error.message,
          userId,
        });
      }
    }

    // ============================================
    // 4. REVOGAR TODOS OS TOKENS (se solicitado)
    // ============================================
    if (revokeAll && userId) {
      // Revogar todos os refresh tokens do usuário no banco
      await refreshTokenRepository.revokeAllByUserId(userId);
      
      // Revogar todos os access tokens do usuário na blacklist
      tokenBlacklist.revokeAllByUserId(userId);

      logger.info('Todos os tokens do usuário foram revogados', { userId });
    }

    logger.info('Logout realizado com sucesso', {
      userId,
      revokeAll,
      hasRefreshToken: !!refreshToken,
    });
  } catch (error: any) {
    logger.error('Erro ao realizar logout', {
      error: error.message,
      stack: error.stack,
    });
    throw new AppError('Erro ao realizar logout', 500);
  }
}
