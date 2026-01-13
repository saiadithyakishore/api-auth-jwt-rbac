// ============================================
// REPOSITORY: Acesso a dados de permissões
// ============================================

import { query } from '../config/database';
import { Permission } from '../types';
import { mapPermissionFromDb } from '../utils/mapper.util';

/**
 * Busca uma permissão por ID
 */
export async function findById(id: number): Promise<Permission | null> {
  const results = await query<any[]>(
    'SELECT * FROM permissions WHERE id = ?',
    [id]
  );
  return results.length > 0 ? mapPermissionFromDb(results[0]) : null;
}

/**
 * Busca uma permissão por nome
 */
export async function findByName(name: string): Promise<Permission | null> {
  const results = await query<any[]>(
    'SELECT * FROM permissions WHERE name = ?',
    [name]
  );
  return results.length > 0 ? mapPermissionFromDb(results[0]) : null;
}

/**
 * Lista todas as permissões
 */
export async function findAll(): Promise<Permission[]> {
  const results = await query<any[]>(
    'SELECT * FROM permissions ORDER BY resource, action'
  );
  return results.map(mapPermissionFromDb);
}

/**
 * Lista permissões por IDs
 */
export async function findByIds(ids: number[]): Promise<Permission[]> {
  if (ids.length === 0) {
    return [];
  }
  
  const placeholders = ids.map(() => '?').join(',');
  const results = await query<any[]>(
    `SELECT * FROM permissions WHERE id IN (${placeholders})`,
    ids
  );
  return results.map(mapPermissionFromDb);
}

/**
 * Busca permissões por recurso
 */
export async function findByResource(resource: string): Promise<Permission[]> {
  const results = await query<any[]>(
    'SELECT * FROM permissions WHERE resource = ? ORDER BY action',
    [resource]
  );
  return results.map(mapPermissionFromDb);
}
