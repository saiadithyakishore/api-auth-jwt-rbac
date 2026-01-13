// ============================================
// MIDDLEWARE: Tratamento centralizado de erros
// ============================================

import { Request, Response, NextFunction } from 'express';
import { AppError } from '../types';
import { errorResponse, internalErrorResponse } from '../utils/response.util';
import { logError } from '../utils/logger.util';

/**
 * Middleware de tratamento centralizado de erros (ENTERPRISE)
 *
 * - Captura todos os erros da aplicação
 * - Retorna respostas padronizadas
 * - Loga erros estruturados para observabilidade
 * - Compatível com TypeScript strict
 */
export function errorHandler(
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction // necessário para Express, ignorado pelo TS
): void {
  // ============================
  // JSON malformado
  // ============================
  if (err instanceof SyntaxError && 'body' in err) {
    logError(err, {
      endpoint: req.path,
      method: req.method,
      type: 'JSON_PARSE_ERROR',
    });

    errorResponse(
      res,
      'JSON inválido no body da requisição',
      400,
      'Verifique a sintaxe do JSON. Exemplo: {"username": "admin", "password": "senha123"}'
    );
    return;
  }

  // ============================
  // Erro operacional (AppError)
  // ============================
  if (err instanceof AppError && err.isOperational) {
    if (err.statusCode >= 500) {
      logError(err, {
        endpoint: req.path,
        method: req.method,
        type: 'OPERATIONAL_ERROR',
      });
    }

    errorResponse(res, err.message, err.statusCode);
    return;
  }

  // ============================
  // Erro não operacional (500)
  // ============================
  logError(err, {
    endpoint: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    type: 'UNHANDLED_ERROR',
  });

  internalErrorResponse(
    res,
    'Erro interno do servidor',
    process.env.NODE_ENV === 'development' ? err.message : undefined
  );
}

/**
 * Wrapper para capturar erros assíncronos
 * Evita try/catch repetitivo em controllers
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
