// ============================================
// CONTROLLER: Endpoints de usuários
// ============================================

import { Request, Response } from 'express';
import * as userService from '../services/user.service';
import { AuthRequest } from '../types';
import {
  successResponse,
  createdResponse,
  errorResponse,
  notFoundResponse,
} from '../utils/response.util';
import {
  validateCreateUser,
  validateUpdateUser,
} from '../utils/validation.util';
import {
  logUserCreated,
  logError,
} from '../utils/logger.util';

/**
 * GET /api/users
 * Lista todos os usuários
 */
export async function listUsers(req: Request, res: Response): Promise<void> {
  try {
    const limit = parseInt(req.query.limit as string, 10) || 50;
    const offset = parseInt(req.query.offset as string, 10) || 0;

    const users = await userService.listUsers(limit, offset);
    successResponse(res, users, 'Usuários listados com sucesso');
  } catch (error: any) {
    logError(error as Error, { endpoint: 'GET /api/users' });
    errorResponse(res, 'Erro ao listar usuários', 500);
  }
}

/**
 * GET /api/users/:id
 * Busca um usuário por ID
 */
export async function getUserById(req: Request, res: Response): Promise<void> {
  const id = parseInt(req.params.id, 10);

  if (isNaN(id)) {
    errorResponse(res, 'ID inválido', 400);
    return;
  }

  try {
    const user = await userService.getUserById(id);
    successResponse(res, user, 'Usuário encontrado');
  } catch (error: any) {
    const statusCode = error.statusCode || 500;

    if (statusCode === 404) {
      notFoundResponse(res, 'Usuário não encontrado');
    } else {
      errorResponse(res, error.message || 'Erro ao buscar usuário', statusCode);
    }
  }
}

/**
 * POST /api/users
 * Cria um novo usuário
 *
 * REGRAS DE NEGÓCIO:
 * - Frontend NÃO pode definir roles (roleIds é IGNORADO)
 * - Todo usuário recebe automaticamente role USER
 * - Apenas ADMIN pode alterar roles via PUT /api/users/:id
 */
export async function createUser(req: Request, res: Response): Promise<void> {
  const authReq = req as AuthRequest;
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  if (!authReq.user) {
    errorResponse(res, 'Usuário não autenticado', 401);
    return;
  }

  try {
    const validatedData = validateCreateUser(req.body);

    const { username, email, password, fullName } = validatedData;

    const userData = {
      username,
      email,
      password,
      fullName,
    };

    const user = await userService.createUser(
      userData,
      authReq.user.id,
      ipAddress,
      userAgent
    );

    logUserCreated(authReq.user.id, user.id, user.username, ipAddress);
    createdResponse(res, user, 'Usuário criado com sucesso');
  } catch (error: any) {
    logError(error as Error, {
      endpoint: 'POST /api/users',
      userId: authReq.user?.id,
    });

    const statusCode = error.statusCode || 500;
    errorResponse(res, error.message || 'Erro ao criar usuário', statusCode);
  }
}

/**
 * PUT /api/users/:id
 * Atualiza um usuário
 */
export async function updateUser(req: Request, res: Response): Promise<void> {
  const authReq = req as AuthRequest;
  const id = parseInt(req.params.id, 10);
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  if (isNaN(id)) {
    errorResponse(res, 'ID inválido', 400);
    return;
  }

  if (!authReq.user) {
    errorResponse(res, 'Usuário não autenticado', 401);
    return;
  }

  try {
    const validatedData = validateUpdateUser(req.body);

    const user = await userService.updateUser(
      id,
      validatedData,
      authReq.user.id,
      ipAddress,
      userAgent
    );

    successResponse(res, user, 'Usuário atualizado com sucesso');
  } catch (error: any) {
    const statusCode = error.statusCode || 500;

    if (statusCode === 404) {
      notFoundResponse(res, 'Usuário não encontrado');
    } else {
      errorResponse(res, error.message || 'Erro ao atualizar usuário', statusCode);
    }
  }
}

/**
 * DELETE /api/users/:id
 * Deleta um usuário
 */
export async function deleteUser(req: Request, res: Response): Promise<void> {
  const authReq = req as AuthRequest;
  const id = parseInt(req.params.id, 10);
  const hardDelete = req.query.hard === 'true';
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  if (isNaN(id)) {
    errorResponse(res, 'ID inválido', 400);
    return;
  }

  if (!authReq.user) {
    errorResponse(res, 'Usuário não autenticado', 401);
    return;
  }

  try {
    const result = await userService.deleteUser(
      id,
      authReq.user.id,
      hardDelete,
      ipAddress,
      userAgent
    );

    successResponse(res, null, result.message);
  } catch (error: any) {
    const statusCode = error.statusCode || 500;

    if (statusCode === 404) {
      notFoundResponse(res, 'Usuário não encontrado');
    } else {
      errorResponse(res, error.message || 'Erro ao deletar usuário', statusCode);
    }
  }
}
