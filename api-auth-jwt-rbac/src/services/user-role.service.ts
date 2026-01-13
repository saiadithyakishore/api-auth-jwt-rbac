// ============================================
// SERVICE: Gerenciamento de Roles de Usuários
// ============================================
// 
// Lógica de negócio para atualização de roles
// Apenas ADMIN pode alterar roles de outros usuários
// ============================================

import * as userRepository from '../repositories/user.repository';
import * as roleRepository from '../repositories/role.repository';
import * as auditRepository from '../repositories/audit.repository';
import { AppError } from '../types';
import { logRoleChange } from '../utils/logger.util';

/**
 * Atualiza roles de um usuário
 * 
 * REGRAS DE NEGÓCIO:
 * 1. Apenas ADMIN pode alterar roles
 * 2. Valida que todas as roles existem no banco
 * 3. Permite múltiplas roles por usuário
 * 4. Registra auditoria completa
 * 5. Retorna roles normalizadas como array de strings
 * 
 * @param userId - ID do usuário a ter roles alteradas
 * @param roleIds - Array de IDs das roles a serem atribuídas
 * @param currentUserId - ID do usuário que está fazendo a alteração (deve ser ADMIN)
 * @param ipAddress - IP do cliente
 * @param userAgent - User agent do cliente
 * @returns Usuário atualizado com roles
 */
export async function updateUserRoles(
  userId: number,
  roleIds: number[],
  currentUserId: number,
  ipAddress?: string,
  userAgent?: string
) {
  // ============================================
  // VALIDAÇÕES INICIAIS
  // ============================================

  // Verificar se usuário existe
  const targetUser = await userRepository.findByIdWithRoles(userId);
  if (!targetUser) {
    throw new AppError('Usuário não encontrado', 404);
  }

  // Não permitir auto-alteração de roles (segurança)
  if (userId === currentUserId) {
    throw new AppError('Não é possível alterar suas próprias roles', 400);
  }

  // ============================================
  // VALIDAR ROLES
  // ============================================

  // Verificar se todas as roles existem
  const roles = await roleRepository.findByIds(roleIds);
  if (roles.length !== roleIds.length) {
    const invalidRoleIds = roleIds.filter(
      (id) => !roles.some((r) => r.id === id)
    );
    throw new AppError(
      `Uma ou mais roles são inválidas: ${invalidRoleIds.join(', ')}`,
      400
    );
  }

  // Verificar se há roles duplicadas
  const uniqueRoleIds = [...new Set(roleIds)];
  if (uniqueRoleIds.length !== roleIds.length) {
    throw new AppError('Roles duplicadas não são permitidas', 400);
  }

  // ============================================
  // CAPTURAR ROLES ANTIGAS PARA AUDITORIA
  // ============================================

  const oldRoles = targetUser.roles.map((r) => r.name);

  // ============================================
  // ATUALIZAR ROLES
  // ============================================

  // Atualizar roles do usuário
  await userRepository.update(userId, { roleIds });

  // Buscar usuário atualizado com novas roles
  const updatedUser = await userRepository.findByIdWithRoles(userId);
  if (!updatedUser) {
    throw new AppError('Erro ao atualizar roles do usuário', 500);
  }

  const newRoles = updatedUser.roles.map((r) => r.name);

  // ============================================
  // AUDITORIA
  // ============================================

  await auditRepository.create({
    userId: currentUserId,
    action: 'USER_ROLES_UPDATED',
    resourceType: 'USER',
    resourceId: userId,
    details: {
      targetUsername: updatedUser.username,
      oldRoles,
      newRoles,
      changedBy: currentUserId,
    },
    ipAddress,
    userAgent,
  });

  // Log estruturado
  logRoleChange(currentUserId, userId, oldRoles, newRoles, ipAddress);

  // ============================================
  // RETORNO PADRONIZADO
  // ============================================

  return {
    id: updatedUser.id,
    username: updatedUser.username,
    email: updatedUser.email,
    fullName: updatedUser.fullName,
    isActive: updatedUser.isActive,
    roles: newRoles, // Array de strings: ["USER", "ADMIN"]
    createdAt: updatedUser.createdAt,
    updatedAt: updatedUser.updatedAt,
  };
}

/**
 * Lista todas as roles disponíveis no sistema
 */
export async function listAvailableRoles() {
  const roles = await roleRepository.findAll();
  return roles.map((role) => ({
    id: role.id,
    name: role.name,
    description: role.description,
  }));
}
