// ============================================
// ROUTES: Debug e Teste (Apenas Desenvolvimento)
// ============================================
// 
// Endpoints para debug e teste de JWT
// REMOVER EM PRODUÇÃO
// ============================================

import { Router, Request, Response } from 'express';
import { verifyAccessToken, extractTokenFromHeader } from '../utils/jwt-advanced.util';
import jwt from 'jsonwebtoken';
import jwtConfig from '../config/jwt.config';

const router = Router();

// Apenas em desenvolvimento - endpoints de debug
// Em produção, este router não deve ser usado

/**
 * GET /api/debug/token
 * Decodifica e mostra informações do token (sem verificar)
 */
router.get('/token', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization || req.headers['authorization'];
  const token = extractTokenFromHeader(authHeader);

  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'Token não fornecido',
    });
  }

  try {
    // Decodificar SEM verificar (apenas para debug)
    const decoded = jwt.decode(token, { complete: true });

    return res.json({
      success: true,
      data: {
        header: decoded?.header,
        payload: decoded?.payload,
        signature: (decoded as any)?.signature?.substring(0, 20) + '...',
        tokenLength: token.length,
        tokenPreview: token.substring(0, 50) + '...',
      },
    });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      message: 'Erro ao decodificar token',
      error: error.message,
    });
  }
});

/**
 * GET /api/debug/verify
 * Verifica token e mostra detalhes da validação
 */
router.get('/verify', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization || req.headers['authorization'];
  const token = extractTokenFromHeader(authHeader);

  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'Token não fornecido',
    });
  }

  try {
    // Verificar token
    const decoded = verifyAccessToken(token);

    return res.json({
      success: true,
      message: 'Token válido',
      data: {
        decoded,
        config: {
          issuer: jwtConfig.issuer,
          audience: jwtConfig.audience,
          algorithm: jwtConfig.algorithm,
          secretLength: jwtConfig.secret.length,
        },
      },
    });
  } catch (error: any) {
    return res.status(401).json({
      success: false,
      message: 'Token inválido',
      error: error.message,
      config: {
        issuer: jwtConfig.issuer,
        audience: jwtConfig.audience,
        algorithm: jwtConfig.algorithm,
        secretLength: jwtConfig.secret.length,
      },
    });
  }
});

/**
 * GET /api/debug/config
 * Mostra configuração JWT atual (sem secrets)
 */
router.get('/config', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
      algorithm: jwtConfig.algorithm,
      accessExpiresIn: jwtConfig.accessExpiresIn,
      refreshExpiresIn: jwtConfig.refreshExpiresIn,
      secretLength: jwtConfig.secret.length,
      hasRefreshSecret: !!jwtConfig.refreshSecret,
      nodeEnv: process.env.NODE_ENV,
    },
  });
});

export default router;
