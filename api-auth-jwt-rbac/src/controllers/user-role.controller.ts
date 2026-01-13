// ============================================
// CONTROLLER: Gerenciamento de Roles
// ============================================

import { Request, Response } from 'express';
import * as userRoleService from '../services/user-role.service';
import { validateUpdateRoles } from '../utils/validation.util';
import { successResponse, errorResponse, forbiddenResponse } from '../utils/response.util';
import { AuthRequest } from '../types';
import { asyncHandler } from '../middlewares/error.middleware';

/**
 * PUT /api/users/:id/roles
 * Atualiza roles de um usuário
 * 
 * Apenas ADMIN pode acessar este endpoint
 * Valida roles existentes e permite múltiplas roles
 */
export async function updateUserRoles(
  req: Request,
  res: Response
): Promise<void> {
  const authReq = req as AuthRequest;
  const userId = parseInt(req.params.id, 10);
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  if (isNaN(userId)) {
    errorResponse(res, 'ID inválido', 400);
    return;
  }

  if (!authReq.user) {
    errorResponse(res, 'Usuário não autenticado', 401);
    return;
  }

  const hasAdminRole = authReq.user.roles?.some((role) => role.toUpperCase() === 'ADMIN');
  if (!hasAdminRole) {
    forbiddenResponse(
      res,
      'Acesso negado. Roles necessárias: ADMIN.'
    );
    return;
  }

  // Validar dados de entrada
  const validatedData = validateUpdateRoles(req.body);

  try {
    const updatedUser = await userRoleService.updateUserRoles(
      userId,
      validatedData.roleIds,
      authReq.user.id,
      ipAddress,
      userAgent
    );

    successResponse(
      res,
      updatedUser,
      'Roles atualizadas com sucesso',
      200
    );
  } catch (error: any) {
    const statusCode = error?.statusCode || 500;
    errorResponse(
      res,
      error?.message || 'Erro ao atualizar roles',
      statusCode
    );
  }
}

/**
 * GET /api/users/roles/available
 * Lista todas as roles disponíveis no sistema
 */
export async function listAvailableRoles(
  _req: Request, // ← corrigido (evita TS6133)
  res: Response
): Promise<void> {
  try {
    const roles = await userRoleService.listAvailableRoles();
    successResponse(
      res,
      roles,
      'Roles disponíveis listadas com sucesso'
    );
  } catch (error: any) {
    errorResponse(res, 'Erro ao listar roles', 500);
  }
}

// Exportar handlers com asyncHandler
export const updateUserRolesHandler = asyncHandler(updateUserRoles);
export const listAvailableRolesHandler = asyncHandler(listAvailableRoles);
