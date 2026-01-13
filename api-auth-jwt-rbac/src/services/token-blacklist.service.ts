// ============================================
// SERVICE: Token Blacklist (ENTERPRISE)
// ============================================
// 
// Gerencia blacklist de tokens revogados
// Implementação em memória (pode ser migrado para Redis em produção)
// ============================================

import { logger } from '../utils/logger.util';

interface BlacklistedToken {
  tokenHash: string;
  expiresAt: number; // Timestamp de expiração
  userId?: number;
  reason?: string; // 'logout', 'revoked', etc.
}

/**
 * Blacklist em memória
 * 
 * ESTRUTURA:
 * Map<tokenHash, { expiresAt, userId, reason }>
 * 
 * LIMITAÇÕES:
 * - Perde dados ao reiniciar servidor
 * - Não compartilha entre instâncias (não é distribuído)
 * 
 * PRODUÇÃO:
 * - Migrar para Redis para persistência e distribuição
 * - Usar TTL automático do Redis
 */
class TokenBlacklistService {
  private blacklist: Map<string, BlacklistedToken> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    if (process.env.NODE_ENV !== 'test') {
      this.startCleanup();
    }
  }
  

  /**
   * Adiciona token à blacklist
   * 
   * @param token - Token JWT completo
   * @param expiresAt - Timestamp de expiração do token
   * @param userId - ID do usuário (opcional)
   * @param reason - Motivo da revogação (opcional)
   */
  add(token: string, expiresAt: Date, userId?: number, reason?: string): void {
    const tokenHash = this.hashToken(token);
    const expiresAtTimestamp = expiresAt.getTime();

    this.blacklist.set(tokenHash, {
      tokenHash,
      expiresAt: expiresAtTimestamp,
      userId,
      reason: reason || 'logout',
    });

    if (process.env.NODE_ENV !== 'production') {
      logger.debug('Token adicionado à blacklist', {
        tokenHash: tokenHash.substring(0, 10) + '...',
        userId,
        reason,
        expiresAt: new Date(expiresAtTimestamp).toISOString(),
      });
    }
  }

  /**
   * Verifica se token está na blacklist
   * 
   * @param token - Token JWT completo
   * @returns true se token está revogado
   */
  isBlacklisted(token: string): boolean {
    const tokenHash = this.hashToken(token);
    const entry = this.blacklist.get(tokenHash);

    if (!entry) {
      return false;
    }

    // Verificar se token expirou (limpar automaticamente)
    if (entry.expiresAt < Date.now()) {
      this.blacklist.delete(tokenHash);
      return false; // Token expirado não precisa estar na blacklist
    }

    return true;
  }

  /**
   * Remove token da blacklist (útil para testes)
   */
  remove(token: string): void {
    const tokenHash = this.hashToken(token);
    this.blacklist.delete(tokenHash);
  }

  /**
   * Remove todos os tokens de um usuário
   */
  revokeAllByUserId(userId: number): void {
    let count = 0;
    for (const [hash, entry] of this.blacklist.entries()) {
      if (entry.userId === userId) {
        this.blacklist.delete(hash);
        count++;
      }
    }

    if (count > 0) {
      logger.info(`Revogados ${count} tokens do usuário ${userId} da blacklist`);
    }
  }

  /**
   * Limpa tokens expirados da blacklist
   */
  private cleanup(): void {
    const now = Date.now();
    let removed = 0;

    for (const [hash, entry] of this.blacklist.entries()) {
      if (entry.expiresAt < now) {
        this.blacklist.delete(hash);
        removed++;
      }
    }

    if (removed > 0 && process.env.NODE_ENV !== 'production') {
      logger.debug(`Limpeza de blacklist: ${removed} tokens expirados removidos`);
    }
  }

  /**
   * Inicia limpeza automática periódica
   */
  private startCleanup(): void {
    // Limpar a cada 1 hora
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60 * 60 * 1000);
  }

  /**
   * Para limpeza automática (útil para testes)
   */
  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Gera hash SHA256 do token para armazenamento
   */
  private hashToken(token: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Retorna estatísticas da blacklist (útil para debug)
   */
  getStats(): { total: number; expired: number } {
    const now = Date.now();
    let expired = 0;

    for (const entry of this.blacklist.values()) {
      if (entry.expiresAt < now) {
        expired++;
      }
    }

    return {
      total: this.blacklist.size,
      expired,
    };
  }
}

// Singleton
export const tokenBlacklist = new TokenBlacklistService();
