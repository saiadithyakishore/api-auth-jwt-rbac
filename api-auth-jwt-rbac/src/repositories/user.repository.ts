// ============================================
// REPOSITORY: Acesso a dados de usuários
// ============================================

import { query } from '../config/database';
import { User, UserWithRoles, CreateUserData, UpdateUserData, UserWithRolesAndPermissions } from '../types';
import { mapUserFromDb, mapRoleFromDb, mapPermissionFromDb } from '../utils/mapper.util';

/**
 * Busca um usuário por ID
 */
export async function findById(id: number): Promise<User | null> {
  const results = await query<any[]>(
    'SELECT * FROM users WHERE id = ?',
    [id]
  );
  return results.length > 0 ? mapUserFromDb(results[0]) : null;
}

/**
 * Busca um usuário por username
 */
export async function findByUsername(username: string): Promise<User | null> {
  const results = await query<any[]>(
    'SELECT * FROM users WHERE username = ?',
    [username]
  );
  return results.length > 0 ? mapUserFromDb(results[0]) : null;
}

/**
 * Busca um usuário por email
 */
export async function findByEmail(email: string): Promise<User | null> {
  const results = await query<any[]>(
    'SELECT * FROM users WHERE email = ?',
    [email]
  );
  return results.length > 0 ? mapUserFromDb(results[0]) : null;
}

/**
 * Busca um usuário por ID com suas roles
 */
export async function findByIdWithRoles(id: number): Promise<UserWithRoles | null> {
  const userResults = await query<any[]>(
    'SELECT * FROM users WHERE id = ?',
    [id]
  );

  if (userResults.length === 0) {
    return null;
  }

  const user = mapUserFromDb(userResults[0]);
  
  // Buscar roles do usuário
  const rolesResults = await query<any[]>(
    `SELECT r.* FROM roles r
     INNER JOIN user_roles ur ON r.id = ur.role_id
     WHERE ur.user_id = ?`,
    [id]
  );

  return {
    ...user,
    roles: rolesResults.map(mapRoleFromDb),
  };
}

/**
 * Busca um usuário por username com suas roles e permissões
 * Busca case-insensitive e ignora espaços em branco
 */
export async function findByUsernameWithRolesAndPermissions(
  username: string
): Promise<UserWithRolesAndPermissions | null> {
  // Busca case-insensitive usando LOWER() e TRIM()
  const userResults = await query<any[]>(
    'SELECT id, username, email, password_hash, full_name, is_active FROM users WHERE LOWER(TRIM(username)) = LOWER(TRIM(?))',
    [username]
  );

  if (userResults.length === 0) {
    return null;
  }

  const dbUser = userResults[0];
  const user = {
    id: dbUser.id,
    username: dbUser.username,
    email: dbUser.email,
    password_hash: dbUser.password_hash,
    full_name: dbUser.full_name,
    is_active: dbUser.is_active === 1 || dbUser.is_active === true,
  };
  
  // Buscar roles do usuário
  const rolesResults = await query<any[]>(
    `SELECT r.* FROM roles r
     INNER JOIN user_roles ur ON r.id = ur.role_id
     WHERE ur.user_id = ?`,
    [user.id]
  );

  // Buscar permissões do usuário através das roles
  const permissionsResults = await query<any[]>(
    `SELECT DISTINCT p.* FROM permissions p
     INNER JOIN role_permissions rp ON p.id = rp.permission_id
     INNER JOIN user_roles ur ON rp.role_id = ur.role_id
     WHERE ur.user_id = ?`,
    [user.id]
  );

  return {
    ...user,
    roles: rolesResults.map(mapRoleFromDb),
    permissions: permissionsResults.map(mapPermissionFromDb),
  };
}

/**
 * Lista todos os usuários (com paginação)
 */
export async function findAll(
  limit: number = 50,
  offset: number = 0
): Promise<User[]> {
  const results = await query<any[]>(
    'SELECT id, username, email, full_name, is_active, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?',
    [limit, offset]
  );
  return results.map(mapUserFromDb);
}

/**
 * Cria um novo usuário
 */
export async function create(userData: CreateUserData, passwordHash: string): Promise<User> {
  const result = await query<any>(
    `INSERT INTO users (username, email, password_hash, full_name)
     VALUES (?, ?, ?, ?)`,
    [userData.username, userData.email, passwordHash, userData.fullName]
  );

  const userId = result.insertId;

  // Associar roles se fornecidas
  if (userData.roleIds && userData.roleIds.length > 0) {
    // Inserir todas as roles de uma vez (mais eficiente e garante atomicidade)
    for (const roleId of userData.roleIds) {
      await query(
        'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
        [userId, roleId]
      );
    }
  }

  const newUser = await findById(userId);
  if (!newUser) {
    throw new Error('Erro ao criar usuário');
  }

  return newUser;
}

/**
 * Atualiza um usuário
 */
export async function update(id: number, userData: UpdateUserData): Promise<User> {
  const updates: string[] = [];
  const values: any[] = [];

  if (userData.email !== undefined) {
    updates.push('email = ?');
    values.push(userData.email);
  }
  if (userData.fullName !== undefined) {
    updates.push('full_name = ?');
    values.push(userData.fullName);
  }
  if (userData.isActive !== undefined) {
    updates.push('is_active = ?');
    values.push(userData.isActive);
  }

  if (updates.length > 0) {
    values.push(id);
    await query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );
  }

  // Atualizar roles se fornecidas
  if (userData.roleIds !== undefined) {
    // Remover roles existentes
    await query('DELETE FROM user_roles WHERE user_id = ?', [id]);
    
    // Adicionar novas roles
    if (userData.roleIds.length > 0) {
      for (const roleId of userData.roleIds) {
        await query(
          'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
          [id, roleId]
        );
      }
    }
  }

  const updatedUser = await findById(id);
  if (!updatedUser) {
    throw new Error('Erro ao atualizar usuário');
  }

  return updatedUser;
}

/**
 * Deleta um usuário (soft delete ou hard delete)
 */
export async function remove(id: number, hardDelete: boolean = false): Promise<void> {
  if (hardDelete) {
    await query('DELETE FROM users WHERE id = ?', [id]);
  } else {
    await query('UPDATE users SET is_active = FALSE WHERE id = ?', [id]);
  }
}

/**
 * Verifica se username já existe
 */
export async function usernameExists(username: string, excludeId?: number): Promise<boolean> {
  let sql = 'SELECT COUNT(*) as count FROM users WHERE username = ?';
  const params: any[] = [username];

  if (excludeId) {
    sql += ' AND id != ?';
    params.push(excludeId);
  }

  const results = await query<{ count: number }[]>(sql, params);
  return results[0].count > 0;
}

/**
 * Verifica se email já existe
 */
export async function emailExists(email: string, excludeId?: number): Promise<boolean> {
  let sql = 'SELECT COUNT(*) as count FROM users WHERE email = ?';
  const params: any[] = [email];

  if (excludeId) {
    sql += ' AND id != ?';
    params.push(excludeId);
  }

  const results = await query<{ count: number }[]>(sql, params);
  return results[0].count > 0;
}

/**
 * Associa uma role a um usuário
 */
export async function associateRole(userId: number, roleId: number): Promise<void> {
  // Verificar se já existe
  const existing = await query<any[]>(
    'SELECT * FROM user_roles WHERE user_id = ? AND role_id = ?',
    [userId, roleId]
  );

  if (existing.length === 0) {
    await query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [userId, roleId]
    );
  }
}
