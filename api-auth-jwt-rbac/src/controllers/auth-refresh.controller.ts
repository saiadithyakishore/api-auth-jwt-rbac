// ============================================
// CONTROLLER: Refresh Token
// ============================================

import { Request, Response } from 'express';
import * as authRefreshService from '../services/auth-refresh.service';
import { successResponse, errorResponse } from '../utils/response.util';
import { z } from 'zod';

const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token é obrigatório'),
});

/**
 * POST /api/auth/refresh-token
 * Renova Access Token usando Refresh Token (COM ROTAÇÃO)
 * 
 * PADRÃO CORPORATIVO:
 * - Gera novo access token
 * - Gera novo refresh token (rotação)
 * - Revoga refresh token antigo
 * - Armazena novo refresh token
 */
export async function refreshToken(req: Request, res: Response): Promise<void> {
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  try {
    // Validar dados
    const validatedData = refreshTokenSchema.parse(req.body);

    const result = await authRefreshService.refreshAccessToken(
      validatedData.refreshToken,
      ipAddress,
      userAgent
    );

    successResponse(res, result, 'Token renovado com sucesso');
  } catch (error: any) {
    const statusCode = error.statusCode || 401;
    errorResponse(res, error.message || 'Erro ao renovar token', statusCode);
  }
}
