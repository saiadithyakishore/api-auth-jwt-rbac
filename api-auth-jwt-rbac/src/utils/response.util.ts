// ============================================
// UTILITÁRIO: Respostas HTTP Padronizadas
// ============================================
// 
// Helper functions para padronizar todas as respostas da API
// Segue padrão enterprise de APIs REST
// ============================================

import { Response } from 'express';
import { ApiResponse } from '../types';

/**
 * Retorna resposta de sucesso padronizada
 * 
 * @param res - Objeto Response do Express
 * @param data - Dados a serem retornados
 * @param message - Mensagem de sucesso (opcional)
 * @param statusCode - Código HTTP (padrão: 200)
 */
export function successResponse<T>(
  res: Response,
  data: T,
  message: string = 'Operação realizada com sucesso',
  statusCode: number = 200
): void {
  const response: ApiResponse<T> = {
    success: true,
    message,
    data,
  };

  res.status(statusCode).json(response);
}

/**
 * Retorna resposta de erro padronizada
 * 
 * @param res - Objeto Response do Express
 * @param message - Mensagem de erro
 * @param statusCode - Código HTTP (padrão: 400)
 * @param error - Detalhes do erro (opcional, apenas em desenvolvimento)
 */
export function errorResponse(
  res: Response,
  message: string,
  statusCode: number = 400,
  error?: string
): void {
  const response: ApiResponse = {
    success: false,
    message,
    error: process.env.NODE_ENV === 'development' ? error : undefined,
  };

  res.status(statusCode).json(response);
}

/**
 * Retorna resposta 201 Created padronizada
 */
export function createdResponse<T>(
  res: Response,
  data: T,
  message: string = 'Recurso criado com sucesso'
): void {
  successResponse(res, data, message, 201);
}

/**
 * Retorna resposta 204 No Content padronizada
 */
export function noContentResponse(res: Response): void {
  res.status(204).send();
}

/**
 * Retorna resposta 401 Unauthorized padronizada
 */
export function unauthorizedResponse(
  res: Response,
  message: string = 'Não autenticado'
): void {
  errorResponse(res, message, 401);
}

/**
 * Retorna resposta 403 Forbidden padronizada
 */
export function forbiddenResponse(
  res: Response,
  message: string = 'Acesso negado'
): void {
  errorResponse(res, message, 403);
}

/**
 * Retorna resposta 404 Not Found padronizada
 */
export function notFoundResponse(
  res: Response,
  message: string = 'Recurso não encontrado'
): void {
  errorResponse(res, message, 404);
}

/**
 * Retorna resposta 409 Conflict padronizada
 */
export function conflictResponse(
  res: Response,
  message: string = 'Conflito na requisição'
): void {
  errorResponse(res, message, 409);
}

/**
 * Retorna resposta 500 Internal Server Error padronizada
 */
export function internalErrorResponse(
  res: Response,
  message: string = 'Erro interno do servidor',
  error?: string
): void {
  errorResponse(res, message, 500, error);
}
