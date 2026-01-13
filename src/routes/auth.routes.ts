// ============================================
// ROUTES: Rotas de autenticação
// ============================================

import { Router } from 'express';
import * as authController from '../controllers/auth.controller';
import { refreshToken } from '../controllers/auth-refresh.controller';
import { logout } from '../controllers/logout.controller';
import { authenticate } from '../middlewares/auth.middleware';
import { asyncHandler } from '../middlewares/error.middleware';

const router = Router();

/**
 * @route   POST /api/auth/register
 * @desc    Registra um novo usuário
 * @access  Public
 */
router.post('/register', asyncHandler(authController.register));

/**
 * @route   POST /api/auth/login
 * @desc    Autentica um usuário e retorna token JWT
 * @access  Public
 */
router.post('/login', asyncHandler(authController.login));

/**
 * @route   GET /api/auth/me
 * @desc    Retorna informações do usuário autenticado
 * @access  Private
 */
router.get('/me', authenticate, asyncHandler(authController.getCurrentUser));

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Renova Access Token usando Refresh Token (com rotação)
 * @access  Public
 * 
 * PADRÃO CORPORATIVO:
 * - Gera novo access token (15 min)
 * - Gera novo refresh token (7 dias) - ROTAÇÃO
 * - Revoga refresh token antigo
 * - Armazena novo refresh token no banco
 */
router.post('/refresh-token', asyncHandler(refreshToken));

/**
 * @route   POST /api/auth/logout
 * @desc    Realiza logout do usuário (revoga tokens)
 * @access  Private - Requer autenticação
 * 
 * AÇÕES:
 * - Adiciona access token à blacklist
 * - Revoga refresh token no banco (se fornecido)
 * - Opcional: revoga todos os tokens do usuário (revokeAll = true)
 */
router.post('/logout', authenticate, asyncHandler(logout));

export default router;
