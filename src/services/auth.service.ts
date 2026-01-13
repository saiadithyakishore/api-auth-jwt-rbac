// ============================================
// SERVICE: Lógica de negócio de autenticação
// ============================================

import * as userRepository from '../repositories/user.repository';
import * as roleRepository from '../repositories/role.repository';
import * as auditRepository from '../repositories/audit.repository';
import { hashPassword, comparePassword } from '../utils/bcrypt.util';
import { generateAccessToken, generateRefreshToken } from '../utils/jwt-advanced.util';
import { validateRegisterData, validateLoginData } from '../utils/validation.util';
import { logAuthAttempt } from '../utils/logger.util';
import { AppError } from '../types';
import {
  LoginRequest,
  RegisterRequest,
  AuthResponse,
  CreateUserData,
} from '../types';

/**
 * Registra um novo usuário no sistema
 */
export async function register(
  registerData: RegisterRequest,
  ipAddress?: string,
  userAgent?: string
): Promise<AuthResponse> {
  // Validações de formato
  validateRegisterData(registerData);

  // Verificar se username já existe
  if (await userRepository.usernameExists(registerData.username)) {
    throw new AppError('Username já está em uso', 409);
  }

  // Verificar se email já existe
  if (await userRepository.emailExists(registerData.email)) {
    throw new AppError('Email já está em uso', 409);
  }

  // Hash da senha
  const passwordHash = await hashPassword(registerData.password);

  // Buscar role USER padrão (todos os usuários registrados recebem role USER)
  const userRole = await roleRepository.findByName('USER');
  if (!userRole) {
    throw new AppError('Role USER não encontrada. Execute o seed.sql primeiro.', 500);
  }

  // Criar usuário com role USER padrão
  const userData: CreateUserData = {
    username: registerData.username,
    email: registerData.email,
    password: registerData.password,
    fullName: registerData.fullName,
    roleIds: [userRole.id], // Atribuir role USER automaticamente
  };

  const user = await userRepository.create(userData, passwordHash);

  // Aguardar um momento para garantir que a transação foi commitada
  // (necessário em alguns casos de pool de conexões)
  
  // Buscar usuário com roles
  const userWithRoles = await userRepository.findByIdWithRoles(user.id);
  if (!userWithRoles) {
    throw new AppError('Erro ao criar usuário', 500);
  }

  // Verificar se a role foi associada corretamente
  if (!userWithRoles.roles || userWithRoles.roles.length === 0) {
    // Se não tiver roles, tentar associar novamente (fallback)
    const defaultRole = await roleRepository.findByName('USER');
    if (defaultRole) {
      await userRepository.associateRole(user.id, defaultRole.id);
      // Buscar novamente
      const retryUser = await userRepository.findByIdWithRoles(user.id);
      if (retryUser && retryUser.roles.length > 0) {
        // Gerar tokens para retry
        const retryRoles = retryUser.roles.map((r) => r.name);
        const retryAccessToken = generateAccessToken({
          userId: retryUser.id,
          username: retryUser.username,
          email: retryUser.email,
          roles: retryRoles,
        });
        const retryRefreshToken = generateRefreshToken({
          userId: retryUser.id,
          username: retryUser.username,
        });

        // Armazenar refresh token
        const refreshTokenRepository = await import('../repositories/refresh-token.repository');
        const expiresInDays = parseInt(process.env.JWT_REFRESH_EXPIRES_IN?.replace('d', '') || '7');
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + expiresInDays);
        await refreshTokenRepository.create(
          retryUser.id,
          retryRefreshToken,
          expiresAt,
          ipAddress,
          userAgent
        );

        return {
          token: retryAccessToken,
          accessToken: retryAccessToken,
          refreshToken: retryRefreshToken,
          user: {
            id: retryUser.id,
            username: retryUser.username,
            email: retryUser.email,
            fullName: retryUser.fullName,
            roles: retryRoles,
          },
        };
      }
    }
    throw new AppError('Erro ao associar role ao usuário', 500);
  }

  // Registrar ação de auditoria
  await auditRepository.create({
    userId: user.id,
    action: 'USER_REGISTERED',
    resourceType: 'USER',
    resourceId: user.id,
    details: { username: user.username, email: user.email },
    ipAddress,
    userAgent,
  });

  // Gerar tokens (Access Token + Refresh Token)
  const roles = userWithRoles.roles.map((r) => r.name);
  const accessToken = generateAccessToken({
    userId: user.id,
    username: user.username,
    email: user.email,
    roles,
  });

  const refreshToken = generateRefreshToken({
    userId: user.id,
    username: user.username,
  });

  // Armazenar refresh token no banco
  const refreshTokenRepository = await import('../repositories/refresh-token.repository');
  const expiresInDays = parseInt(process.env.JWT_REFRESH_EXPIRES_IN?.replace('d', '') || '7');
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiresInDays);
  await refreshTokenRepository.create(
    user.id,
    refreshToken,
    expiresAt,
    ipAddress,
    userAgent
  );

  return {
    token: accessToken, // Compatibilidade
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      roles,
    },
  };
}

/**
 * Autentica um usuário e retorna token JWT
 */
export async function login(
  loginData: LoginRequest,
  ipAddress?: string,
  userAgent?: string
): Promise<AuthResponse> {
  // Validações de formato
  validateLoginData(loginData);

  // Normalizar username (trim e case-insensitive)
  const normalizedUsername = loginData.username.trim();
  
  // Buscar usuário com roles e permissões (busca case-insensitive)
  const user = await userRepository.findByUsernameWithRolesAndPermissions(
    normalizedUsername
  );

  if (!user) {
    throw new AppError('Credenciais inválidas', 401);
  }

  // Verificar se usuário está ativo
  // user.is_active é boolean no tipo, mas MySQL pode retornar como number (0/1)
  // Converter para boolean de forma segura
  const isActiveValue = user.is_active as unknown as boolean | number;
  const isActive = isActiveValue === 1 || isActiveValue === true;
  if (!isActive) {
    throw new AppError('Usuário inativo', 403);
  }

  // Normalizar senha (trim)
  const normalizedPassword = loginData.password.trim();

  // Verificar senha
  const passwordMatch = await comparePassword(
    normalizedPassword,
    user.password_hash
  );

  if (!passwordMatch) {
    throw new AppError('Credenciais inválidas', 401);
  }

  // Registrar ação de auditoria
  await auditRepository.create({
    userId: user.id,
    action: 'USER_LOGIN',
    resourceType: 'USER',
    resourceId: user.id,
    details: { username: user.username },
    ipAddress,
    userAgent,
  });

  // Gerar tokens (Access Token + Refresh Token)
  const roles = user.roles.map((r) => r.name);
  const accessToken = generateAccessToken({
    userId: user.id,
    username: user.username,
    email: user.email,
    roles,
  });

  const refreshToken = generateRefreshToken({
    userId: user.id,
    username: user.username,
  });

  // Armazenar refresh token no banco
  const expiresInDays = parseInt(process.env.JWT_REFRESH_EXPIRES_IN?.replace('d', '') || '7');
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiresInDays);

  // Importar repository de refresh tokens
  const refreshTokenRepository = await import('../repositories/refresh-token.repository');
  await refreshTokenRepository.create(
    user.id,
    refreshToken,
    expiresAt,
    ipAddress,
    userAgent
  );

  logAuthAttempt(normalizedUsername, true, ipAddress);

  return {
    token: accessToken, // Mantido para compatibilidade
    accessToken, // Novo campo
    refreshToken, // Novo campo
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.full_name,
      roles,
    },
  };
}

/**
 * Busca informações do usuário autenticado
 */
export async function getCurrentUser(userId: number) {
  const user = await userRepository.findByIdWithRoles(userId);

  if (!user) {
    throw new AppError('Usuário não encontrado', 404);
  }

  if (!user.isActive) {
    throw new AppError('Usuário inativo', 403);
  }

  const roles = user.roles.map((r) => r.name);

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    roles,
    isActive: user.isActive,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}
