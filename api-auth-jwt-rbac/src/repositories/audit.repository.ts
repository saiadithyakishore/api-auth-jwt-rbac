// ============================================
// REPOSITORY: Acesso a dados de auditoria
// ============================================

import { query } from '../config/database';

interface AuditLog {
  id: number;
  userId: number | null;
  action: string;
  resourceType: string | null;
  resourceId: number | null;
  details: any | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

interface CreateAuditLogData {
  userId?: number;
  action: string;
  resourceType?: string;
  resourceId?: number;
  details?: any;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Cria um registro de auditoria
 */
export async function create(auditData: CreateAuditLogData): Promise<AuditLog> {
  const result = await query<any>(
    `INSERT INTO audit_logs 
     (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      auditData.userId || null,
      auditData.action,
      auditData.resourceType || null,
      auditData.resourceId || null,
      auditData.details ? JSON.stringify(auditData.details) : null,
      auditData.ipAddress || null,
      auditData.userAgent || null,
    ]
  );

  const logs = await query<AuditLog[]>(
    'SELECT * FROM audit_logs WHERE id = ?',
    [result.insertId]
  );

  return logs[0];
}

/**
 * Lista logs de auditoria (com paginação)
 */
export async function findAll(
  limit: number = 50,
  offset: number = 0
): Promise<AuditLog[]> {
  return query<AuditLog[]>(
    `SELECT * FROM audit_logs 
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`,
    [limit, offset]
  );
}

/**
 * Busca logs por usuário
 */
export async function findByUserId(
  userId: number,
  limit: number = 50,
  offset: number = 0
): Promise<AuditLog[]> {
  return query<AuditLog[]>(
    `SELECT * FROM audit_logs 
     WHERE user_id = ? 
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`,
    [userId, limit, offset]
  );
}

/**
 * Busca logs por ação
 */
export async function findByAction(
  action: string,
  limit: number = 50,
  offset: number = 0
): Promise<AuditLog[]> {
  return query<AuditLog[]>(
    `SELECT * FROM audit_logs 
     WHERE action = ? 
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`,
    [action, limit, offset]
  );
}
