// ============================================
// CONTROLLER: Endpoints de autenticação
// ============================================

import { Request, Response } from 'express';
import * as authService from '../services/auth.service';
import { AuthRequest } from '../types';
import { successResponse, createdResponse, errorResponse } from '../utils/response.util';
import { validateRegister, validateLogin } from '../utils/validation.util';
import { logAuthAttempt } from '../utils/logger.util';

/**
 * POST /api/auth/register
 * Registra um novo usuário
 */
export async function register(req: Request, res: Response): Promise<void> {
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  try {
    // Validar dados de entrada
    const validatedData = validateRegister(req.body);

    const result = await authService.register(
      validatedData,
      ipAddress,
      userAgent
    );

    logAuthAttempt(validatedData.username, true, ipAddress);
    createdResponse(res, result, 'Usuário registrado com sucesso');
  } catch (error: any) {
    logAuthAttempt(req.body.username || 'unknown', false, ipAddress, error.message);
    const statusCode = error.statusCode || 500;
    errorResponse(res, error.message || 'Erro ao registrar usuário', statusCode);
  }
}

/**
 * POST /api/auth/login
 * Autentica um usuário e retorna token JWT
 */
export async function login(req: Request, res: Response): Promise<void> {
  const ipAddress = req.ip || req.socket.remoteAddress || undefined;
  const userAgent = req.get('user-agent') || undefined;

  try {
    // Validar dados de entrada
    const validatedData = validateLogin(req.body);

    const result = await authService.login(
      validatedData,
      ipAddress,
      userAgent
    );

    logAuthAttempt(validatedData.username, true, ipAddress);
    successResponse(res, result, 'Login realizado com sucesso');
  } catch (error: any) {
    logAuthAttempt(req.body.username || 'unknown', false, ipAddress, error.message);
    const statusCode = error.statusCode || 401;
    errorResponse(res, error.message || 'Erro ao fazer login', statusCode);
  }
}

/**
 * GET /api/auth/me
 * Retorna informações do usuário autenticado
 */
export async function getCurrentUser(req: Request, res: Response): Promise<void> {
  const authReq = req as AuthRequest;
  
  if (!authReq.user) {
    errorResponse(res, 'Usuário não autenticado', 401);
    return;
  }

  try {
    const user = await authService.getCurrentUser(authReq.user.id);
    successResponse(res, user, 'Dados do usuário recuperados com sucesso');
  } catch (error: any) {
    const statusCode = error.statusCode || 500;
    errorResponse(res, error.message || 'Erro ao buscar usuário', statusCode);
  }
}
