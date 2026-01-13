// ============================================
// CONFIGURAÇÃO: JWT Centralizada (ENTERPRISE)
// ============================================
// 
// Configuração única e centralizada para JWT
// Evita inconsistências entre geração e validação
// ============================================

import dotenv from 'dotenv';

dotenv.config();

// ============================================
// VALIDAÇÃO DE VARIÁVEIS DE AMBIENTE
// ============================================

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_ACCESS_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

// Validação rigorosa em produção
if (process.env.NODE_ENV === 'production') {
  if (!JWT_SECRET || JWT_SECRET === 'default_secret_change_in_production') {
    throw new Error(
      '❌ FATAL: JWT_SECRET não configurado! Configure JWT_SECRET no .env antes de iniciar em produção.'
    );
  }
  if (!JWT_REFRESH_SECRET || JWT_REFRESH_SECRET === JWT_SECRET) {
    throw new Error(
      '❌ FATAL: JWT_REFRESH_SECRET não configurado ou igual a JWT_SECRET! Configure JWT_REFRESH_SECRET diferente de JWT_SECRET.'
    );
  }
} else {
  // Em desenvolvimento, usar fallback mas avisar
  if (!JWT_SECRET || JWT_SECRET === 'default_secret_change_in_production') {
    console.warn('⚠️  WARNING: JWT_SECRET não configurado. Usando secret padrão (INSEGURO para produção).');
  }
}

// ============================================
// CONFIGURAÇÕES JWT
// ============================================

// ============================================
// INTERFACE DE CONFIGURAÇÃO JWT
// ============================================

export interface JWTConfig {
  secret: string;
  refreshSecret: string;
  accessExpiresIn: string;
  refreshExpiresIn: string;
  issuer: 'api-auth-rbac';
  audience: 'api-users';
  algorithm: 'HS256';
}

// ============================================
// CONFIGURAÇÕES JWT
// ============================================

export const jwtConfig: JWTConfig = {
  // Secrets (garantir que são sempre strings)
  secret: JWT_SECRET || 'default_secret_change_in_production',
  refreshSecret: JWT_REFRESH_SECRET || (JWT_SECRET || 'default_secret') + '_refresh',
  
  // Expiração
  accessExpiresIn: JWT_ACCESS_EXPIRES_IN,
  refreshExpiresIn: JWT_REFRESH_EXPIRES_IN,
  
  // Issuer e Audience (IMPORTANTE: devem ser EXATAMENTE iguais na geração e validação)
  issuer: 'api-auth-rbac',
  audience: 'api-users',
  
  // Algoritmo (HS256 é o padrão e mais seguro)
  algorithm: 'HS256',
};

// ============================================
// VALIDAÇÃO DE CONFIGURAÇÃO
// ============================================

if (!jwtConfig.secret || jwtConfig.secret.length < 32) {
  console.warn('⚠️  WARNING: JWT_SECRET muito curto. Use pelo menos 32 caracteres em produção.');
}

// Log de configuração (apenas em desenvolvimento)
if (process.env.NODE_ENV !== 'production') {
  console.log('🔐 JWT Config:', {
    secretLength: jwtConfig.secret.length,
    hasRefreshSecret: !!jwtConfig.refreshSecret,
    accessExpiresIn: jwtConfig.accessExpiresIn,
    refreshExpiresIn: jwtConfig.refreshExpiresIn,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
  });
}

export default jwtConfig;
