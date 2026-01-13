// ============================================
// REPOSITORY: Refresh Tokens
// ============================================
// 
// Acesso a dados de refresh tokens no banco
// ============================================

import { query } from '../config/database';
import crypto from 'crypto';

export interface RefreshTokenRecord {
  id: number;
  userId: number;
  tokenHash: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
  revokedAt: Date | null;
  ipAddress: string | null;
  userAgent: string | null;
}

/**
 * Gera hash SHA256 do token para armazenamento seguro
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Cria um novo refresh token no banco
 */
export async function create(
  userId: number,
  token: string,
  expiresAt: Date,
  ipAddress?: string,
  userAgent?: string
): Promise<RefreshTokenRecord> {
  const tokenHash = hashToken(token);

  const result = await query<any>(
    `INSERT INTO refresh_tokens 
     (user_id, token_hash, expires_at, ip_address, user_agent) 
     VALUES (?, ?, ?, ?, ?)`,
    [userId, tokenHash, expiresAt, ipAddress || null, userAgent || null]
  );

  const inserted = await query<any[]>(
    'SELECT * FROM refresh_tokens WHERE id = ?',
    [result.insertId]
  );

  return mapFromDb(inserted[0]);
}

/**
 * Busca refresh token por hash
 */
export async function findByTokenHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
  const results = await query<any[]>(
    `SELECT * FROM refresh_tokens 
     WHERE token_hash = ? AND is_revoked = FALSE AND expires_at > NOW()`,
    [tokenHash]
  );

  return results.length > 0 ? mapFromDb(results[0]) : null;
}

/**
 * Busca refresh token por token (gera hash e busca)
 */
export async function findByToken(token: string): Promise<RefreshTokenRecord | null> {
  const tokenHash = hashToken(token);
  return findByTokenHash(tokenHash);
}

/**
 * Revoga um refresh token (logout)
 */
export async function revoke(tokenHash: string): Promise<void> {
  await query(
    `UPDATE refresh_tokens 
     SET is_revoked = TRUE, revoked_at = NOW() 
     WHERE token_hash = ?`,
    [tokenHash]
  );
}

/**
 * Revoga todos os refresh tokens de um usuário
 */
export async function revokeAllByUserId(userId: number): Promise<void> {
  await query(
    `UPDATE refresh_tokens 
     SET is_revoked = TRUE, revoked_at = NOW() 
     WHERE user_id = ? AND is_revoked = FALSE`,
    [userId]
  );
}

/**
 * Remove tokens expirados (limpeza)
 */
export async function deleteExpired(): Promise<number> {
  const result = await query<any>(
    'DELETE FROM refresh_tokens WHERE expires_at < NOW()'
  );
  return result.affectedRows || 0;
}

/**
 * Remove tokens revogados antigos (limpeza - mais de 30 dias)
 */
export async function deleteOldRevoked(): Promise<number> {
  const result = await query<any>(
    `DELETE FROM refresh_tokens 
     WHERE is_revoked = TRUE AND revoked_at < DATE_SUB(NOW(), INTERVAL 30 DAY)`
  );
  return result.affectedRows || 0;
}

/**
 * Mapeia dados do banco para tipo TypeScript
 */
function mapFromDb(row: any): RefreshTokenRecord {
  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    isRevoked: row.is_revoked === 1 || row.is_revoked === true,
    expiresAt: new Date(row.expires_at),
    createdAt: new Date(row.created_at),
    revokedAt: row.revoked_at ? new Date(row.revoked_at) : null,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
  };
}
