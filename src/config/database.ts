// ============================================
// CONFIGURAÇÃO: Conexão com MySQL
// ============================================

import mysql, { FieldPacket, Pool, PoolConnection, PoolOptions } from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

type QueryParams = any[] | undefined;

interface UserRow {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  full_name: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
}

interface RoleRow {
  id: number;
  name: string;
  description: string | null;
  created_at: Date;
  updated_at: Date;
}

interface UserRoleRow {
  user_id: number;
  role_id: number;
}

interface PermissionRow {
  id: number;
  name: string;
  description: string | null;
  resource: string;
  action: string;
  created_at: Date;
  updated_at: Date;
}

interface RolePermissionRow {
  role_id: number;
  permission_id: number;
}

interface RefreshTokenRow {
  id: number;
  user_id: number;
  token_hash: string;
  is_revoked: boolean;
  expires_at: Date;
  created_at: Date;
  revoked_at: Date | null;
  ip_address: string | null;
  user_agent: string | null;
}

interface AuditLogRow {
  id: number;
  user_id: number | null;
  action: string;
  resource_type: string | null;
  resource_id: number | null;
  details: any;
  ip_address: string | null;
  user_agent: string | null;
  created_at: Date;
}

class InMemoryDatabase {
  private users: UserRow[] = [];
  private roles: RoleRow[] = [];
  private userRoles: UserRoleRow[] = [];
  private permissions: PermissionRow[] = [];
  private rolePermissions: RolePermissionRow[] = [];
  private refreshTokens: RefreshTokenRow[] = [];
  private auditLogs: AuditLogRow[] = [];
  private ids = {
    users: 1,
    roles: 1,
    permissions: 1,
    refreshTokens: 1,
    auditLogs: 1,
  };

  constructor() {
    this.reset();
  }

  reset(): void {
    this.users = [];
    this.roles = [];
    this.userRoles = [];
    this.permissions = [];
    this.rolePermissions = [];
    this.refreshTokens = [];
    this.auditLogs = [];
    this.ids = {
      users: 1,
      roles: 1,
      permissions: 1,
      refreshTokens: 1,
      auditLogs: 1,
    };
    this.seedDefaults();
  }

  async query<T = any>(sql: string, params: QueryParams = []): Promise<T> {
    const normalized = this.normalizeSql(sql);

    // ROLES
    if (normalized.startsWith('INSERT INTO ROLES')) {
      const [name, description] = params || [];
      return this.insertRole(String(name), description ?? null) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM ROLES WHERE ID = ?')) {
      const [id] = params || [];
      return this.roles.filter((role) => role.id === Number(id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM ROLES WHERE NAME = ?')) {
      const [name] = params || [];
      return this.roles.filter((role) => role.name === String(name)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM ROLES ORDER BY NAME')) {
      const sorted = [...this.roles].sort((a, b) => a.name.localeCompare(b.name));
      return sorted as unknown as T;
    }

    if (normalized.startsWith('DELETE FROM ROLES WHERE ID = ?')) {
      const [id] = params || [];
      const roleId = Number(id);
      const before = this.roles.length;
      this.roles = this.roles.filter((role) => role.id !== roleId);
      this.userRoles = this.userRoles.filter((relation) => relation.role_id !== roleId);
      this.rolePermissions = this.rolePermissions.filter((relation) => relation.role_id !== roleId);
      const affectedRows = Math.max(0, before - this.roles.length);
      return { affectedRows } as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM ROLES WHERE ID IN (')) {
      const ids = (params || []).map((id) => Number(id));
      return this.roles.filter((role) => ids.includes(role.id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT R.* FROM ROLES R INNER JOIN USER_ROLES UR ON R.ID = UR.ROLE_ID WHERE UR.USER_ID = ?')) {
      const [userId] = params || [];
      const roleIds = this.userRoles.filter((ur) => ur.user_id === Number(userId)).map((ur) => ur.role_id);
      return this.roles.filter((role) => roleIds.includes(role.id)) as unknown as T;
    }

    // PERMISSIONS
    if (normalized.startsWith('SELECT P.* FROM PERMISSIONS P INNER JOIN ROLE_PERMISSIONS RP ON P.ID = RP.PERMISSION_ID WHERE RP.ROLE_ID = ?')) {
      const [roleId] = params || [];
      const permissionIds = this.rolePermissions
        .filter((rp) => rp.role_id === Number(roleId))
        .map((rp) => rp.permission_id);
      return this.permissions.filter((permission) => permissionIds.includes(permission.id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT DISTINCT P.* FROM PERMISSIONS P INNER JOIN ROLE_PERMISSIONS RP ON P.ID = RP.PERMISSION_ID INNER JOIN USER_ROLES UR ON RP.ROLE_ID = UR.ROLE_ID WHERE UR.USER_ID = ?')) {
      const [userId] = params || [];
      const rolesForUser = this.userRoles.filter((ur) => ur.user_id === Number(userId)).map((ur) => ur.role_id);
      const permissionIds = this.rolePermissions
        .filter((rp) => rolesForUser.includes(rp.role_id))
        .map((rp) => rp.permission_id);
      const uniquePermissions = this.permissions.filter((permission) => permissionIds.includes(permission.id));
      return uniquePermissions as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM PERMISSIONS WHERE ID = ?')) {
      const [id] = params || [];
      return this.permissions.filter((permission) => permission.id === Number(id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM PERMISSIONS WHERE NAME = ?')) {
      const [name] = params || [];
      return this.permissions.filter((permission) => permission.name === String(name)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM PERMISSIONS WHERE ID IN (')) {
      const ids = (params || []).map((id) => Number(id));
      return this.permissions.filter((permission) => ids.includes(permission.id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM PERMISSIONS WHERE RESOURCE = ? ORDER BY ACTION')) {
      const [resource] = params || [];
      const filtered = this.permissions
        .filter((permission) => permission.resource === String(resource))
        .sort((a, b) => a.action.localeCompare(b.action));
      return filtered as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM PERMISSIONS ORDER BY RESOURCE, ACTION')) {
      const sorted = [...this.permissions].sort((a, b) => {
        if (a.resource === b.resource) {
          return a.action.localeCompare(b.action);
        }
        return a.resource.localeCompare(b.resource);
      });
      return sorted as unknown as T;
    }

    // USERS
    if (normalized.startsWith('INSERT INTO USERS')) {
      return this.insertUser(normalized, params || []) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM USERS WHERE ID = ?')) {
      const [id] = params || [];
      return this.users.filter((user) => user.id === Number(id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM USERS WHERE USERNAME = ?')) {
      const [username] = params || [];
      return this.users.filter((user) => user.username === String(username)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM USERS WHERE EMAIL = ?')) {
      const [email] = params || [];
      return this.users.filter((user) => user.email === String(email)) as unknown as T;
    }

    if (normalized.startsWith('SELECT ID, USERNAME, EMAIL, PASSWORD_HASH, FULL_NAME, IS_ACTIVE FROM USERS WHERE LOWER(TRIM(USERNAME)) = LOWER(TRIM(?))')) {
      const [username] = params || [];
      const normalizedUsername = String(username).trim().toLowerCase();
      const matches = this.users.filter((user) => user.username.trim().toLowerCase() === normalizedUsername);
      return matches as unknown as T;
    }

    if (normalized.startsWith('SELECT ID, USERNAME, EMAIL, FULL_NAME, IS_ACTIVE, CREATED_AT, UPDATED_AT FROM USERS ORDER BY CREATED_AT DESC LIMIT ? OFFSET ?')) {
      const [limit = 50, offset = 0] = (params || []).map((value) => Number(value));
      const sorted = [...this.users].sort(
        (a, b) => b.created_at.getTime() - a.created_at.getTime()
      );
      return sorted.slice(offset, offset + limit) as unknown as T;
    }

    if (normalized.startsWith('SELECT COUNT(*) AS COUNT FROM USERS WHERE USERNAME = ?')) {
      const [username, excludeId] = params || [];
      const count = this.users.filter((user) => {
        const sameUsername = user.username === String(username);
        const differentId = excludeId ? user.id !== Number(excludeId) : true;
        return sameUsername && differentId;
      }).length;
      return [{ count }] as unknown as T;
    }

    if (normalized.startsWith('SELECT COUNT(*) AS COUNT FROM USERS WHERE EMAIL = ?')) {
      const [email, excludeId] = params || [];
      const count = this.users.filter((user) => {
        const sameEmail = user.email === String(email);
        const differentId = excludeId ? user.id !== Number(excludeId) : true;
        return sameEmail && differentId;
      }).length;
      return [{ count }] as unknown as T;
    }

    if (normalized.startsWith('UPDATE USERS SET IS_ACTIVE = FALSE WHERE ID = ?')) {
      const [id] = params || [];
      const user = this.users.find((u) => u.id === Number(id));
      if (user) {
        user.is_active = false;
        user.updated_at = new Date();
        return { affectedRows: 1 } as unknown as T;
      }
      return { affectedRows: 0 } as unknown as T;
    }

    if (normalized.startsWith('UPDATE USERS SET')) {
      const [id] = params ? params.slice(-1) : [];
      const user = this.users.find((u) => u.id === Number(id));
      if (!user) {
        return { affectedRows: 0 } as unknown as T;
      }
      const setSection = normalized.split('UPDATE USERS SET ')[1].split(' WHERE ')[0];
      const fields = setSection.split(',').map((part) => part.trim());
      const values = (params || []).slice(0, fields.length);
      fields.forEach((field, index) => {
        const value = values[index];
        if (field.startsWith('EMAIL')) {
          user.email = String(value);
        }
        if (field.startsWith('FULL_NAME')) {
          user.full_name = String(value);
        }
        if (field.startsWith('IS_ACTIVE')) {
          user.is_active = Boolean(value);
        }
      });
      user.updated_at = new Date();
      return { affectedRows: 1 } as unknown as T;
    }

    if (normalized.startsWith('DELETE FROM USERS WHERE ID = ?')) {
      const [id] = params || [];
      const before = this.users.length;
      this.users = this.users.filter((user) => user.id !== Number(id));
      this.userRoles = this.userRoles.filter((ur) => ur.user_id !== Number(id));
      const affectedRows = before !== this.users.length ? 1 : 0;
      return { affectedRows } as unknown as T;
    }

    // USER ROLES
    if (normalized.startsWith('INSERT INTO USER_ROLES')) {
      const [userId, roleId] = params || [];
      return this.insertUserRole(Number(userId), Number(roleId)) as unknown as T;
    }

    if (normalized.startsWith('DELETE FROM USER_ROLES WHERE USER_ID = ?')) {
      const [userId] = params || [];
      const before = this.userRoles.length;
      this.userRoles = this.userRoles.filter((ur) => ur.user_id !== Number(userId));
      const affectedRows = Math.max(0, before - this.userRoles.length);
      return { affectedRows } as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM USER_ROLES WHERE USER_ID = ? AND ROLE_ID = ?')) {
      const [userId, roleId] = params || [];
      return this.userRoles.filter(
        (ur) => ur.user_id === Number(userId) && ur.role_id === Number(roleId)
      ) as unknown as T;
    }

    // REFRESH TOKENS
    if (normalized.startsWith('INSERT INTO REFRESH_TOKENS')) {
      const [userId, tokenHash, expiresAt, ipAddress, userAgent] = params || [];
      const now = new Date();
      const newToken: RefreshTokenRow = {
        id: this.ids.refreshTokens++,
        user_id: Number(userId),
        token_hash: String(tokenHash),
        is_revoked: false,
        expires_at: new Date(expiresAt),
        created_at: now,
        revoked_at: null,
        ip_address: ipAddress ? String(ipAddress) : null,
        user_agent: userAgent ? String(userAgent) : null,
      };
      this.refreshTokens.push(newToken);
      return { insertId: newToken.id, affectedRows: 1 } as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM REFRESH_TOKENS WHERE ID = ?')) {
      const [id] = params || [];
      return this.refreshTokens.filter((token) => token.id === Number(id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM REFRESH_TOKENS WHERE TOKEN_HASH = ? AND IS_REVOKED = FALSE AND EXPIRES_AT > NOW()')) {
      const [tokenHash] = params || [];
      const now = new Date();
      const rows = this.refreshTokens.filter(
        (token) =>
          token.token_hash === String(tokenHash) &&
          token.is_revoked === false &&
          token.expires_at > now
      );
      return rows as unknown as T;
    }

    if (normalized.startsWith('UPDATE REFRESH_TOKENS SET IS_REVOKED = TRUE, REVOKED_AT = NOW() WHERE TOKEN_HASH = ?')) {
      const [tokenHash] = params || [];
      let affectedRows = 0;
      this.refreshTokens = this.refreshTokens.map((token) => {
        if (token.token_hash === String(tokenHash)) {
          affectedRows += 1;
          return { ...token, is_revoked: true, revoked_at: new Date() };
        }
        return token;
      });
      return { affectedRows } as unknown as T;
    }

    if (normalized.startsWith('UPDATE REFRESH_TOKENS SET IS_REVOKED = TRUE, REVOKED_AT = NOW() WHERE USER_ID = ? AND IS_REVOKED = FALSE')) {
      const [userId] = params || [];
      let affectedRows = 0;
      this.refreshTokens = this.refreshTokens.map((token) => {
        if (token.user_id === Number(userId) && token.is_revoked === false) {
          affectedRows += 1;
          return { ...token, is_revoked: true, revoked_at: new Date() };
        }
        return token;
      });
      return { affectedRows } as unknown as T;
    }

    if (normalized.startsWith('DELETE FROM REFRESH_TOKENS WHERE EXPIRES_AT < NOW()')) {
      const now = new Date();
      const before = this.refreshTokens.length;
      this.refreshTokens = this.refreshTokens.filter((token) => token.expires_at >= now);
      const affectedRows = Math.max(0, before - this.refreshTokens.length);
      return { affectedRows } as unknown as T;
    }

    if (normalized.startsWith('DELETE FROM REFRESH_TOKENS WHERE IS_REVOKED = TRUE AND REVOKED_AT < DATE_SUB(NOW(), INTERVAL 30 DAY)')) {
      const threshold = new Date();
      threshold.setDate(threshold.getDate() - 30);
      const before = this.refreshTokens.length;
      this.refreshTokens = this.refreshTokens.filter((token) => {
        if (!token.is_revoked || !token.revoked_at) {
          return true;
        }
        return token.revoked_at >= threshold;
      });
      const affectedRows = Math.max(0, before - this.refreshTokens.length);
      return { affectedRows } as unknown as T;
    }

    // AUDIT LOGS
    if (normalized.startsWith('INSERT INTO AUDIT_LOGS')) {
      const [
        userId,
        action,
        resourceType,
        resourceId,
        details,
        ipAddress,
        userAgent,
      ] = params || [];
      const now = new Date();
      const log: AuditLogRow = {
        id: this.ids.auditLogs++,
        user_id: userId !== null && userId !== undefined ? Number(userId) : null,
        action: String(action),
        resource_type: resourceType ? String(resourceType) : null,
        resource_id: resourceId !== null && resourceId !== undefined ? Number(resourceId) : null,
        details: details ? JSON.parse(String(details)) : null,
        ip_address: ipAddress ? String(ipAddress) : null,
        user_agent: userAgent ? String(userAgent) : null,
        created_at: now,
      };
      this.auditLogs.push(log);
      return { insertId: log.id, affectedRows: 1 } as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM AUDIT_LOGS WHERE ID = ?')) {
      const [id] = params || [];
      return this.auditLogs.filter((log) => log.id === Number(id)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM AUDIT_LOGS WHERE USER_ID = ? ORDER BY CREATED_AT DESC LIMIT ? OFFSET ?')) {
      const [userId, limit = 50, offset = 0] = params || [];
      const filtered = this.auditLogs
        .filter((log) => log.user_id === Number(userId))
        .sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
      return filtered.slice(offset, offset + Number(limit)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM AUDIT_LOGS WHERE ACTION = ? ORDER BY CREATED_AT DESC LIMIT ? OFFSET ?')) {
      const [action, limit = 50, offset = 0] = params || [];
      const filtered = this.auditLogs
        .filter((log) => log.action === String(action))
        .sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
      return filtered.slice(offset, offset + Number(limit)) as unknown as T;
    }

    if (normalized.startsWith('SELECT * FROM AUDIT_LOGS ORDER BY CREATED_AT DESC LIMIT ? OFFSET ?')) {
      const [limit = 50, offset = 0] = params || [];
      const sorted = [...this.auditLogs].sort(
        (a, b) => b.created_at.getTime() - a.created_at.getTime()
      );
      return sorted.slice(offset, offset + Number(limit)) as unknown as T;
    }

    throw new Error(`Query não suportada em ambiente de teste: ${sql}`);
  }

  async transaction<T>(callback: (connection: PoolConnection) => Promise<T>): Promise<T> {
    const queryFn: PoolConnection['query'] = async (
      sql: string | mysql.QueryOptions,
      values?: any
    ): Promise<[any, FieldPacket[]]> => {
      const result = await this.query(sql as string, values as any[]);
      return [result, []];
    };

    const executeFn: PoolConnection['execute'] = async (
      sql: string | mysql.QueryOptions,
      values?: any
    ): Promise<[any, FieldPacket[]]> => {
      const result = await this.query(sql as string, values as any[]);
      return [result, []];
    };

    const connection: Partial<PoolConnection> = {
      query: queryFn,
      execute: executeFn,
      release: () => undefined,
      beginTransaction: async () => undefined,
      commit: async () => undefined,
      rollback: async () => undefined,
    };
    return callback(connection as PoolConnection);
  }

  private normalizeSql(sql: string): string {
    return sql.replace(/\s+/g, ' ').trim().toUpperCase();
  }

  private insertRole(name: string, description: string | null): { insertId: number; affectedRows: number } {
    const existing = this.roles.find((role) => role.name === name);
    if (existing) {
      return { insertId: existing.id, affectedRows: 0 };
    }
    const now = new Date();
    const role: RoleRow = {
      id: this.ids.roles++,
      name,
      description,
      created_at: now,
      updated_at: now,
    };
    this.roles.push(role);
    return { insertId: role.id, affectedRows: 1 };
  }

  private insertUser(normalizedSql: string, params: any[]): { insertId: number; affectedRows: number } {
    const hasIsActive = normalizedSql.includes('IS_ACTIVE');
    const [username, email, passwordHash, fullName, isActiveParam] = params;
    const now = new Date();
    const user: UserRow = {
      id: this.ids.users++,
      username: String(username),
      email: String(email),
      password_hash: String(passwordHash),
      full_name: String(fullName),
      is_active: hasIsActive ? Boolean(isActiveParam) : true,
      created_at: now,
      updated_at: now,
    };
    this.users.push(user);
    return { insertId: user.id, affectedRows: 1 };
  }

  private insertUserRole(userId: number, roleId: number): { insertId: number; affectedRows: number } {
    const exists = this.userRoles.some(
      (relation) => relation.user_id === userId && relation.role_id === roleId
    );
    if (!exists) {
      this.userRoles.push({ user_id: userId, role_id: roleId });
      return { insertId: 0, affectedRows: 1 };
    }
    return { insertId: 0, affectedRows: 0 };
  }

  private seedDefaults(): void {
    const now = new Date();

    const defaultPermissions: Array<Omit<PermissionRow, 'id'>> = [
      { name: 'USER_CREATE', description: 'Permite criar novos usuários', resource: 'USER', action: 'CREATE', created_at: now, updated_at: now },
      { name: 'USER_READ', description: 'Permite visualizar usuários', resource: 'USER', action: 'READ', created_at: now, updated_at: now },
      { name: 'USER_UPDATE', description: 'Permite atualizar usuários', resource: 'USER', action: 'UPDATE', created_at: now, updated_at: now },
      { name: 'USER_DELETE', description: 'Permite deletar usuários', resource: 'USER', action: 'DELETE', created_at: now, updated_at: now },
      { name: 'ROLE_CREATE', description: 'Permite criar novas roles', resource: 'ROLE', action: 'CREATE', created_at: now, updated_at: now },
      { name: 'ROLE_READ', description: 'Permite visualizar roles', resource: 'ROLE', action: 'READ', created_at: now, updated_at: now },
      { name: 'ROLE_UPDATE', description: 'Permite atualizar roles', resource: 'ROLE', action: 'UPDATE', created_at: now, updated_at: now },
      { name: 'ROLE_DELETE', description: 'Permite deletar roles', resource: 'ROLE', action: 'DELETE', created_at: now, updated_at: now },
      { name: 'PERMISSION_CREATE', description: 'Permite criar novas permissões', resource: 'PERMISSION', action: 'CREATE', created_at: now, updated_at: now },
      { name: 'PERMISSION_READ', description: 'Permite visualizar permissões', resource: 'PERMISSION', action: 'READ', created_at: now, updated_at: now },
      { name: 'PERMISSION_UPDATE', description: 'Permite atualizar permissões', resource: 'PERMISSION', action: 'UPDATE', created_at: now, updated_at: now },
      { name: 'PERMISSION_DELETE', description: 'Permite deletar permissões', resource: 'PERMISSION', action: 'DELETE', created_at: now, updated_at: now },
      { name: 'AUDIT_READ', description: 'Permite visualizar logs de auditoria', resource: 'AUDIT', action: 'READ', created_at: now, updated_at: now },
    ];

    this.permissions = defaultPermissions.map((permission) => ({
      ...permission,
      id: this.ids.permissions++,
    }));

    const adminRoleId = this.insertRole('ADMIN', 'Administrador do sistema com acesso total').insertId;
    const managerRoleId = this.insertRole('MANAGER', 'Gerente com permissões de gerenciamento').insertId;
    const userRoleId = this.insertRole('USER', 'Usuário padrão com permissões básicas').insertId;

    const adminPermissionIds = this.permissions.map((permission) => permission.id);
    const managerPermissionNames = new Set([
      'USER_CREATE',
      'USER_READ',
      'USER_UPDATE',
      'ROLE_READ',
      'PERMISSION_READ',
      'AUDIT_READ',
    ]);
    const managerPermissionIds = this.permissions
      .filter((permission) => managerPermissionNames.has(permission.name))
      .map((permission) => permission.id);
    const userPermissionIds = this.permissions
      .filter((permission) => permission.name === 'USER_READ')
      .map((permission) => permission.id);

    adminPermissionIds.forEach((permissionId) => {
      this.rolePermissions.push({ role_id: adminRoleId, permission_id: permissionId });
    });

    managerPermissionIds.forEach((permissionId) => {
      this.rolePermissions.push({ role_id: managerRoleId, permission_id: permissionId });
    });

    userPermissionIds.forEach((permissionId) => {
      this.rolePermissions.push({ role_id: userRoleId, permission_id: permissionId });
    });
  }
}

// Interface para configuração do banco
interface DatabaseConfig extends PoolOptions {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

const isTestEnv = process.env.NODE_ENV === 'test';

// Configuração do pool de conexões
const dbConfig: DatabaseConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'api_auth_rbac',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

const testDb = isTestEnv ? new InMemoryDatabase() : null;

// Criar pool de conexões (apenas fora de teste)
const pool: Pool | null = isTestEnv ? null : mysql.createPool(dbConfig);

// Função para testar conexão
export async function testConnection(): Promise<void> {
  if (isTestEnv) {
    return;
  }
  try {
    const connection = await pool!.getConnection();
    if (process.env.NODE_ENV !== 'test') {
      console.log('✅ Conexão com MySQL estabelecida com sucesso');
    }
    connection.release();
  } catch (error) {
    if (process.env.NODE_ENV !== 'test') {
      console.error('❌ Erro ao conectar com MySQL:', error);
    }
    throw error;
  }
}

// Função para executar queries
export async function query<T = any>(sql: string, params?: any[]): Promise<T> {
  if (isTestEnv && testDb) {
    return testDb.query<T>(sql, params);
  }

  const [results] = await pool!.execute(sql, params);
  return results as T;
}

// Função para executar transações
export async function transaction<T>(
  callback: (connection: PoolConnection) => Promise<T>
): Promise<T> {
  if (isTestEnv && testDb) {
    return testDb.transaction(callback);
  }

  const connection = await pool!.getConnection();
  await connection.beginTransaction();

  try {
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

export function resetTestDatabase(): void {
  if (isTestEnv && testDb) {
    testDb.reset();
  }
}

export default pool as Pool | null;
