// ============================================
// ROUTES: Rotas de usuários
// ============================================

import { Router } from 'express';
import * as userController from '../controllers/user.controller';
import {
  updateUserRolesHandler,
  listAvailableRolesHandler,
} from '../controllers/user-role.controller';
import {
  authenticate,
  requireAuthAndPermission,
} from '../middlewares/auth.middleware';
import { requireRoles } from '../middlewares/requireRoles.middleware';
import { asyncHandler } from '../middlewares/error.middleware';
import { AuthRequest } from '../types';
import { forbiddenResponse, unauthorizedResponse } from '../utils/response.util';

const router = Router();

const ensureAdmin = (req: any, res: any, next: any): void => {
  const authReq = req as AuthRequest;
  if (!authReq.user) {
    unauthorizedResponse(res, 'Usuário não autenticado');
    return;
  }

  const hasAdmin = authReq.user.roles?.some((role) => role.toUpperCase() === 'ADMIN');
  if (!hasAdmin) {
    forbiddenResponse(res, 'Acesso negado. Roles necessárias: ADMIN.');
    return;
  }

  next();
};

/**
 * @route   GET /api/users
 * @desc    Lista todos os usuários
 * @access  Private - Requer permissão USER_READ
 */
router.get(
  '/',
  authenticate,
  requireAuthAndPermission('USER_READ'),
  asyncHandler(userController.listUsers)
);

/**
 * @route   GET /api/users/:id
 * @desc    Busca um usuário por ID
 * @access  Private - Requer permissão USER_READ
 */
router.get(
  '/:id',
  authenticate,
  requireAuthAndPermission('USER_READ'),
  asyncHandler(userController.getUserById)
);

/**
 * @route   POST /api/users
 * @desc    Cria um novo usuário
 * @access  Private - Requer permissão USER_CREATE
 */
router.post(
  '/',
  authenticate,
  requireAuthAndPermission('USER_CREATE'),
  asyncHandler(userController.createUser)
);

/**
 * @route   PUT /api/users/:id
 * @desc    Atualiza um usuário
 * @access  Private - Requer permissão USER_UPDATE
 */
router.put(
  '/:id',
  authenticate,
  requireAuthAndPermission('USER_UPDATE'),
  asyncHandler(userController.updateUser)
);

/**
 * @route   DELETE /api/users/:id
 * @desc    Deleta um usuário
 * @access  Private - Requer permissão USER_DELETE
 */
router.delete(
  '/:id',
  authenticate,
  requireAuthAndPermission('USER_DELETE'),
  asyncHandler(userController.deleteUser)
);

/**
 * @route   PUT /api/users/:id/roles
 * @desc    Atualiza roles de um usuário
 * @access  Private - Requer role ADMIN
 *
 * Apenas usuários com role ADMIN podem alterar roles de outros usuários.
 * Permite múltiplas roles por usuário.
 * Valida que todas as roles existem no banco.
 */
router.put(
  '/:id/roles',
  authenticate,
  ensureAdmin,
  requireRoles('ADMIN'),
  updateUserRolesHandler
);

/**
 * @route   GET /api/users/roles/available
 * @desc    Lista todas as roles disponíveis no sistema
 * @access  Private - Requer autenticação
 */
router.get(
  '/roles/available',
  authenticate,
  listAvailableRolesHandler
);

export default router;
