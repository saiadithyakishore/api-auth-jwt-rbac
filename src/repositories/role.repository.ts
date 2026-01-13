// ============================================
// REPOSITORY: Acesso a dados de roles
// ============================================

import { query } from '../config/database';
import { Role, RoleWithPermissions } from '../types';
import { mapRoleFromDb, mapPermissionFromDb } from '../utils/mapper.util';

/**
 * Busca uma role por ID
 */
export async function findById(id: number): Promise<Role | null> {
  const results = await query<any[]>(
    'SELECT * FROM roles WHERE id = ?',
    [id]
  );
  return results.length > 0 ? mapRoleFromDb(results[0]) : null;
}

/**
 * Busca uma role por nome
 */
export async function findByName(name: string): Promise<Role | null> {
  const results = await query<any[]>(
    'SELECT * FROM roles WHERE name = ?',
    [name]
  );
  return results.length > 0 ? mapRoleFromDb(results[0]) : null;
}

/**
 * Busca uma role por ID com suas permissões
 */
export async function findByIdWithPermissions(id: number): Promise<RoleWithPermissions | null> {
  const roleResults = await query<any[]>(
    'SELECT * FROM roles WHERE id = ?',
    [id]
  );

  if (roleResults.length === 0) {
    return null;
  }

  const role = mapRoleFromDb(roleResults[0]);
  
  // Buscar permissões da role
  const permissionsResults = await query<any[]>(
    `SELECT p.* FROM permissions p
     INNER JOIN role_permissions rp ON p.id = rp.permission_id
     WHERE rp.role_id = ?`,
    [id]
  );

  return {
    ...role,
    permissions: permissionsResults.map(mapPermissionFromDb),
  };
}

/**
 * Lista todas as roles
 */
export async function findAll(): Promise<Role[]> {
  const results = await query<any[]>(
    'SELECT * FROM roles ORDER BY name'
  );
  return results.map(mapRoleFromDb);
}

/**
 * Lista roles por IDs
 */
export async function findByIds(ids: number[]): Promise<Role[]> {
  if (ids.length === 0) {
    return [];
  }
  
  const placeholders = ids.map(() => '?').join(',');
  const results = await query<any[]>(
    `SELECT * FROM roles WHERE id IN (${placeholders})`,
    ids
  );
  return results.map(mapRoleFromDb);
}
