// ============================================
// SERVICE: Lógica de negócio de usuários
// ============================================

import * as userRepository from '../repositories/user.repository';
import * as roleRepository from '../repositories/role.repository';
import * as auditRepository from '../repositories/audit.repository';
import { hashPassword } from '../utils/bcrypt.util';
import { validateRegisterData } from '../utils/validation.util';
import { AppError } from '../types';
import { CreateUserData, UpdateUserData } from '../types';

/**
 * Lista todos os usuários
 */
export async function listUsers(limit: number = 50, offset: number = 0) {
  const users = await userRepository.findAll(limit, offset);
  
  return users.map(user => ({
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    isActive: user.isActive,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  }));
}

/**
 * Busca um usuário por ID
 */
export async function getUserById(id: number) {
  const user = await userRepository.findByIdWithRoles(id);

  if (!user) {
    throw new AppError('Usuário não encontrado', 404);
  }

  // Retornar roles como array de strings (padrão da API)
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    isActive: user.isActive,
    roles: user.roles.map((r) => r.name), // Array de strings: ["USER"]
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

/**
 * Cria um novo usuário
 * 
 * REGRAS DE NEGÓCIO (RBAC):
 * 1. Frontend NÃO pode definir roles na criação (campo roleIds é IGNORADO)
 * 2. Todo usuário criado recebe AUTOMATICAMENTE a role USER
 * 3. Apenas ADMIN pode alterar roles posteriormente via PUT /api/users/:id
 * 4. Retorno padronizado: roles como array de strings ["USER"]
 */
export async function createUser(
  userData: CreateUserData,
  currentUserId: number,
  ipAddress?: string,
  userAgent?: string
) {
  // ============================================
  // VALIDAÇÕES DE ENTRADA
  // ============================================
  validateRegisterData({
    username: userData.username,
    email: userData.email,
    password: userData.password,
    fullName: userData.fullName,
  });

  // Verificar se username já existe
  if (await userRepository.usernameExists(userData.username)) {
    throw new AppError('Username já está em uso', 409);
  }

  // Verificar se email já existe
  if (await userRepository.emailExists(userData.email)) {
    throw new AppError('Email já está em uso', 409);
  }

  // ============================================
  // REGRA DE NEGÓCIO: IGNORAR roleIds DO FRONTEND
  // ============================================
  // Por segurança, o frontend NÃO pode definir roles na criação
  // Todo usuário recebe role USER padrão, independente do que for enviado
  // Apenas ADMIN pode alterar roles via PUT /api/users/:id
  
  // Buscar role USER padrão (OBRIGATÓRIA)
  const defaultUserRole = await roleRepository.findByName('USER');
  if (!defaultUserRole) {
    throw new AppError(
      'Role USER não encontrada no sistema. Execute database/seed.sql para criar as roles padrão.',
      500
    );
  }

  // FORÇAR role USER (ignorar qualquer roleIds enviado)
  userData.roleIds = [defaultUserRole.id];

  // ============================================
  // CRIAÇÃO DO USUÁRIO
  // ============================================
  // Hash da senha
  const passwordHash = await hashPassword(userData.password);

  // Criar usuário com role USER
  const user = await userRepository.create(userData, passwordHash);

  // ============================================
  // VERIFICAÇÃO E FALLBACK (Garantia de Integridade)
  // ============================================
  // Verificar se a role foi associada corretamente
  let userWithRoles = await userRepository.findByIdWithRoles(user.id);
  
  if (!userWithRoles || !userWithRoles.roles || userWithRoles.roles.length === 0) {
    // Fallback: tentar associar role USER novamente
    await userRepository.associateRole(user.id, defaultUserRole.id);
    
    // Buscar novamente após fallback
    userWithRoles = await userRepository.findByIdWithRoles(user.id);
    
    // Se ainda não tiver roles, é um erro crítico
    if (!userWithRoles || !userWithRoles.roles || userWithRoles.roles.length === 0) {
      throw new AppError(
        'Erro crítico: Não foi possível associar role USER ao usuário. Verifique a integridade do banco de dados.',
        500
      );
    }
  }

  // ============================================
  // AUDITORIA
  // ============================================
  await auditRepository.create({
    userId: currentUserId,
    action: 'USER_CREATED',
    resourceType: 'USER',
    resourceId: user.id,
    details: {
      createdUsername: user.username,
      createdEmail: user.email,
      assignedRoles: userWithRoles.roles.map((r) => r.name),
    },
    ipAddress,
    userAgent,
  });

  // ============================================
  // RETORNO PADRONIZADO
  // ============================================
  // Retornar roles como array de strings (padrão da API)
  // Formato: ["USER"] em vez de [{id, name, description}]
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    isActive: user.isActive,
    roles: userWithRoles.roles.map((r) => r.name), // Array de strings, não objetos
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

/**
 * Atualiza um usuário
 */
export async function updateUser(
  id: number,
  userData: UpdateUserData,
  currentUserId: number,
  ipAddress?: string,
  userAgent?: string
) {
  // Verificar se usuário existe
  const existingUser = await userRepository.findById(id);
  if (!existingUser) {
    throw new AppError('Usuário não encontrado', 404);
  }

  // Validar email se fornecido
  if (userData.email && userData.email !== existingUser.email) {
    if (await userRepository.emailExists(userData.email, id)) {
      throw new AppError('Email já está em uso', 409);
    }
  }

  // Validar roles se fornecidas
  if (userData.roleIds && userData.roleIds.length > 0) {
    const roles = await roleRepository.findByIds(userData.roleIds);
    if (roles.length !== userData.roleIds.length) {
      throw new AppError('Uma ou mais roles são inválidas', 400);
    }
  }

  // Atualizar usuário
  const updatedUser = await userRepository.update(id, userData);

  // Registrar ação de auditoria
  await auditRepository.create({
    userId: currentUserId,
    action: 'USER_UPDATED',
    resourceType: 'USER',
    resourceId: id,
    details: {
      updatedFields: Object.keys(userData),
      updatedUsername: updatedUser.username,
    },
    ipAddress,
    userAgent,
  });

  // Buscar usuário com roles para retorno
  const userWithRoles = await userRepository.findByIdWithRoles(id);
  if (!userWithRoles) {
    throw new AppError('Erro ao atualizar usuário', 500);
  }

  // Retornar roles como array de strings (padrão da API)
  return {
    id: updatedUser.id,
    username: updatedUser.username,
    email: updatedUser.email,
    fullName: updatedUser.fullName,
    isActive: updatedUser.isActive,
    roles: userWithRoles.roles.map((r) => r.name), // Array de strings: ["USER", "ADMIN"]
    createdAt: updatedUser.createdAt,
    updatedAt: updatedUser.updatedAt,
  };
}

/**
 * Deleta um usuário
 */
export async function deleteUser(
  id: number,
  currentUserId: number,
  hardDelete: boolean = false,
  ipAddress?: string,
  userAgent?: string
) {
  // Verificar se usuário existe
  const existingUser = await userRepository.findById(id);
  if (!existingUser) {
    throw new AppError('Usuário não encontrado', 404);
  }

  // Não permitir auto-deleção
  if (id === currentUserId) {
    throw new AppError('Não é possível deletar seu próprio usuário', 400);
  }

  // Deletar usuário
  await userRepository.remove(id, hardDelete);

  // Registrar ação de auditoria
  await auditRepository.create({
    userId: currentUserId,
    action: hardDelete ? 'USER_DELETED_HARD' : 'USER_DELETED',
    resourceType: 'USER',
    resourceId: id,
    details: {
      deletedUsername: existingUser.username,
      deletedEmail: existingUser.email,
    },
    ipAddress,
    userAgent,
  });

  return { message: 'Usuário deletado com sucesso' };
}
