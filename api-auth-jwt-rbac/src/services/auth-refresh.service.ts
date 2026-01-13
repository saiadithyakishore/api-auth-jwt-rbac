// ============================================
// SERVICE: Refresh Token (ENTERPRISE)
// ============================================
// 
// Lógica de negócio para renovação de tokens com rotação
// Implementa padrão corporativo de refresh tokens
// ============================================

import * as userRepository from '../repositories/user.repository';
import * as refreshTokenRepository from '../repositories/refresh-token.repository';
import { 
  generateAccessToken, 
  generateRefreshToken, 
  verifyRefreshToken 
} from '../utils/jwt-advanced.util';
import { AppError } from '../types';
import { logAuthAttempt } from '../utils/logger.util';
import jwtConfig from '../config/jwt.config';

/**
 * Renova Access Token usando Refresh Token (COM ROTAÇÃO)
 * 
 * PADRÃO CORPORATIVO:
 * 1. Verifica refresh token (validade, não revogado)
 * 2. Busca usuário e valida
 * 3. Gera novo access token
 * 4. Gera novo refresh token (rotação)
 * 5. Revoga refresh token antigo
 * 6. Armazena novo refresh token
 * 
 * @param refreshToken - Refresh token válido (será revogado após uso)
 * @param ipAddress - IP do cliente
 * @param userAgent - User agent do cliente
 * @returns Novo Access Token e novo Refresh Token
 */
export async function refreshAccessToken(
  refreshToken: string,
  ipAddress?: string,
  userAgent?: string
): Promise<{ accessToken: string; refreshToken: string }> {
  // ============================================
  // 1. VERIFICAR REFRESH TOKEN (JWT)
  // ============================================
  let decoded: { userId: number; username: string };
  try {
    decoded = verifyRefreshToken(refreshToken);
  } catch (error: any) {
    throw new AppError('Refresh token inválido ou expirado', 401);
  }

  // ============================================
  // 2. VERIFICAR SE TOKEN ESTÁ NO BANCO E NÃO FOI REVOGADO
  // ============================================
  const tokenRecord = await refreshTokenRepository.findByToken(refreshToken);

  if (!tokenRecord) {
    throw new AppError('Refresh token não encontrado ou já foi revogado', 401);
  }

  if (tokenRecord.isRevoked) {
    throw new AppError('Refresh token foi revogado (logout realizado)', 401);
  }

  if (tokenRecord.expiresAt < new Date()) {
    throw new AppError('Refresh token expirado', 401);
  }

  // ============================================
  // 3. BUSCAR USUÁRIO E VALIDAR
  // ============================================
  const user = await userRepository.findByIdWithRoles(decoded.userId);

  if (!user) {
    throw new AppError('Usuário não encontrado', 404);
  }

  if (!user.isActive) {
    throw new AppError('Usuário inativo', 403);
  }

  // ============================================
  // 4. GERAR NOVO ACCESS TOKEN
  // ============================================
  const roles = user.roles.map((r) => r.name);
  const newAccessToken = generateAccessToken({
    userId: user.id,
    username: user.username,
    email: user.email,
    roles,
  });

  // ============================================
  // 5. GERAR NOVO REFRESH TOKEN (ROTAÇÃO)
  // ============================================
  const newRefreshToken = generateRefreshToken({
    userId: user.id,
    username: user.username,
  });

  // Calcular data de expiração do novo refresh token
  const expiresInDays = parseInt(jwtConfig.refreshExpiresIn.replace('d', '')) || 7;
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiresInDays);

  // ============================================
  // 6. REVOGAR REFRESH TOKEN ANTIGO
  // ============================================
  await refreshTokenRepository.revoke(tokenRecord.tokenHash);

  // ============================================
  // 7. ARMAZENAR NOVO REFRESH TOKEN
  // ============================================
  await refreshTokenRepository.create(
    user.id,
    newRefreshToken,
    expiresAt,
    ipAddress,
    userAgent
  );

  // ============================================
  // 8. LOG E RETORNO
  // ============================================
  logAuthAttempt(user.username, true, ipAddress, 'Token refreshed with rotation');

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  };
}
