// ============================================
// CONTROLLER: Logout
// ============================================

import { Request, Response } from 'express';
import * as logoutService from '../services/logout.service';
import { extractTokenFromHeader } from '../utils/jwt-advanced.util';
import { successResponse, errorResponse, unauthorizedResponse } from '../utils/response.util';
import { z } from 'zod';

const logoutSchema = z.object({
  refreshToken: z.string().optional(),
  revokeAll: z.boolean().optional().default(false),
});

/**
 * POST /api/auth/logout
 * Realiza logout do usuário
 * 
 * Revoga:
 * - Access token (adicionado à blacklist)
 * - Refresh token (se fornecido, revogado no banco)
 * - Todos os tokens (se revokeAll = true)
 */
export async function logout(req: Request, res: Response): Promise<void> {
  try {
    // ============================================
    // 1. EXTRAIR ACCESS TOKEN DO HEADER
    // ============================================
    const authHeader = req.headers.authorization || req.headers['authorization'];
    const accessToken = extractTokenFromHeader(authHeader);

    if (!accessToken) {
      unauthorizedResponse(res, 'Token não fornecido. Envie no header: Authorization: Bearer <token>');
      return;
    }

    // ============================================
    // 2. VALIDAR BODY (refreshToken e revokeAll são opcionais)
    // ============================================
    let refreshToken: string | undefined;
    let revokeAll: boolean = false;

    if (req.body && Object.keys(req.body).length > 0) {
      try {
        const validatedData = logoutSchema.parse(req.body);
        refreshToken = validatedData.refreshToken;
        revokeAll = validatedData.revokeAll || false;
      } catch (error: any) {
        // Se validação falhar, continuar sem body (todos os campos são opcionais)
        if (error instanceof z.ZodError) {
          // Apenas logar, não falhar
          console.warn('Body inválido no logout, ignorando:', error.errors);
        }
      }
    }

    // ============================================
    // 3. EXECUTAR LOGOUT
    // ============================================
    await logoutService.logout(accessToken, refreshToken, revokeAll);

    // ============================================
    // 4. RETORNAR SUCESSO
    // ============================================
    successResponse(res, { message: 'Logout realizado com sucesso' }, 'Logout realizado com sucesso');
  } catch (error: any) {
    const statusCode = error.statusCode || 500;
    errorResponse(res, error.message || 'Erro ao realizar logout', statusCode);
  }
}
