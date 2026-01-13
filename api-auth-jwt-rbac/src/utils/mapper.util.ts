// ============================================
// UTILITÁRIO: Mapeamento de dados do banco
// ============================================

/**
 * Converte campos snake_case do banco para camelCase do TypeScript
 */
export function mapUserFromDb(dbUser: any): any {
  return {
    id: dbUser.id,
    username: dbUser.username,
    email: dbUser.email,
    passwordHash: dbUser.password_hash,
    fullName: dbUser.full_name,
    isActive: dbUser.is_active === 1 || dbUser.is_active === true,
    createdAt: dbUser.created_at,
    updatedAt: dbUser.updated_at,
  };
}

/**
 * Converte campos snake_case do banco para camelCase de Role
 */
export function mapRoleFromDb(dbRole: any): any {
  return {
    id: dbRole.id,
    name: dbRole.name,
    description: dbRole.description,
    createdAt: dbRole.created_at,
    updatedAt: dbRole.updated_at,
  };
}

/**
 * Converte campos snake_case do banco para camelCase de Permission
 */
export function mapPermissionFromDb(dbPermission: any): any {
  return {
    id: dbPermission.id,
    name: dbPermission.name,
    description: dbPermission.description,
    resource: dbPermission.resource,
    action: dbPermission.action,
    createdAt: dbPermission.created_at,
    updatedAt: dbPermission.updated_at,
  };
}
