// ============================================
// UTILITÁRIO: Validações com Zod
// ============================================
// 
// Validações robustas usando Zod para garantir
// integridade dos dados em todas as camadas
// ============================================

import { z } from 'zod';
import { AppError } from '../types';

// ============================================
// SCHEMAS DE VALIDAÇÃO
// ============================================

/**
 * Schema de validação para registro de usuário
 */
export const registerSchema = z.object({
  username: z
    .string()
    .min(3, 'Username deve ter no mínimo 3 caracteres')
    .max(20, 'Username deve ter no máximo 20 caracteres')
    .regex(
      /^[a-zA-Z0-9_]+$/,
      'Username pode conter apenas letras, números e underscore'
    ),
  email: z
    .string()
    .email('Formato de email inválido')
    .max(100, 'Email muito longo (máximo 100 caracteres)'),
  password: z
    .string()
    .min(6, 'Senha deve ter no mínimo 6 caracteres')
    .max(100, 'Senha muito longa (máximo 100 caracteres)')
    .regex(/[a-zA-Z]/, 'Senha deve conter pelo menos uma letra')
    .regex(/[0-9]/, 'Senha deve conter pelo menos um número'),
  fullName: z
    .string()
    .min(2, 'Nome completo deve ter no mínimo 2 caracteres')
    .max(100, 'Nome completo muito longo (máximo 100 caracteres)'),
});

/**
 * Schema de validação para login
 */
export const loginSchema = z.object({
  username: z
    .string()
    .min(3, 'Username inválido')
    .max(20, 'Username inválido'),
  password: z
    .string()
    .min(6, 'Senha inválida')
    .max(100, 'Senha inválida'),
});

/**
 * Schema de validação para criação de usuário (admin)
 */
export const createUserSchema = z.object({
  username: z
    .string()
    .min(3, 'Username deve ter no mínimo 3 caracteres')
    .max(20, 'Username deve ter no máximo 20 caracteres')
    .regex(
      /^[a-zA-Z0-9_]+$/,
      'Username pode conter apenas letras, números e underscore'
    ),
  email: z
    .string()
    .email('Formato de email inválido')
    .max(100, 'Email muito longo (máximo 100 caracteres)'),
  password: z
    .string()
    .min(6, 'Senha deve ter no mínimo 6 caracteres')
    .max(100, 'Senha muito longa (máximo 100 caracteres)')
    .regex(/[a-zA-Z]/, 'Senha deve conter pelo menos uma letra')
    .regex(/[0-9]/, 'Senha deve conter pelo menos um número'),
  fullName: z
    .string()
    .min(2, 'Nome completo deve ter no mínimo 2 caracteres')
    .max(100, 'Nome completo muito longo (máximo 100 caracteres)'),
  // roleIds é opcional e será ignorado na criação, mas validamos se enviado
  roleIds: z.array(z.number().int().positive()).optional(),
});

/**
 * Schema de validação para atualização de usuário
 */
export const updateUserSchema = z.object({
  email: z
    .string()
    .email('Formato de email inválido')
    .max(100, 'Email muito longo (máximo 100 caracteres)')
    .optional(),
  fullName: z
    .string()
    .min(2, 'Nome completo deve ter no mínimo 2 caracteres')
    .max(100, 'Nome completo muito longo (máximo 100 caracteres)')
    .optional(),
  isActive: z.boolean().optional(),
  roleIds: z.array(z.number().int().positive()).optional(),
});

/**
 * Schema de validação para atualização de roles
 */
export const updateRolesSchema = z.object({
  roleIds: z
    .array(z.number().int().positive(), {
      required_error: 'roleIds é obrigatório',
      invalid_type_error: 'roleIds deve ser um array de números',
    })
    .min(1, 'Deve ter pelo menos uma role')
    .max(10, 'Máximo de 10 roles por usuário'),
});

// ============================================
// FUNÇÕES DE VALIDAÇÃO
// ============================================

/**
 * Valida dados usando um schema Zod
 * 
 * @param schema - Schema Zod para validação
 * @param data - Dados a serem validados
 * @returns Dados validados e parseados
 * @throws AppError se validação falhar
 */
export function validate<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Pegar primeira mensagem de erro ou todas
      const errorMessages = error.errors.map((err) => {
        const path = err.path.join('.');
        return path ? `${path}: ${err.message}` : err.message;
      });

      throw new AppError(
        errorMessages.join('; ') || 'Dados inválidos',
        400
      );
    }
    throw new AppError('Erro de validação', 400);
  }
}

/**
 * Valida dados de registro
 */
export function validateRegister(data: unknown) {
  return validate(registerSchema, data);
}

/**
 * Valida dados de login
 */
export function validateLogin(data: unknown) {
  return validate(loginSchema, data);
}

/**
 * Valida dados de criação de usuário
 */
export function validateCreateUser(data: unknown) {
  return validate(createUserSchema, data);
}

/**
 * Valida dados de atualização de usuário
 */
export function validateUpdateUser(data: unknown) {
  return validate(updateUserSchema, data);
}

/**
 * Valida dados de atualização de roles
 */
export function validateUpdateRoles(data: unknown) {
  return validate(updateRolesSchema, data);
}

// ============================================
// FUNÇÕES DE COMPATIBILIDADE (Legacy)
// ============================================
// Mantidas para compatibilidade com código existente
// TODO: Migrar todo código para usar as novas funções com Zod

/**
 * @deprecated Use validateRegister em vez disso
 */
export function validateRegisterData(data: {
  username?: string;
  email?: string;
  password?: string;
  fullName?: string;
}): void {
  if (!data.username || !data.email || !data.password || !data.fullName) {
    throw new AppError('Todos os campos são obrigatórios', 400);
  }
  validateRegister(data);
}

/**
 * @deprecated Use validateLogin em vez disso
 */
export function validateLoginData(data: { username?: string; password?: string }): void {
  if (!data.username || !data.password) {
    throw new AppError('Username e senha são obrigatórios', 400);
  }
  validateLogin(data);
}
