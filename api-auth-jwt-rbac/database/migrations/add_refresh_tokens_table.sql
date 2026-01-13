-- ============================================
-- MIGRATION: Tabela refresh_tokens
-- Descrição: Armazena refresh tokens para rotação e invalidação
-- ============================================

USE api_auth_rbac;

-- ============================================
-- TABELA: refresh_tokens
-- Descrição: Armazena refresh tokens ativos para controle de rotação
-- ============================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL COMMENT 'ID do usuário dono do token',
    token_hash VARCHAR(255) NOT NULL COMMENT 'Hash do refresh token (SHA256)',
    is_revoked BOOLEAN DEFAULT FALSE COMMENT 'Flag para revogar token (logout)',
    expires_at TIMESTAMP NOT NULL COMMENT 'Data de expiração do token',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de criação',
    revoked_at TIMESTAMP NULL COMMENT 'Data de revogação (logout)',
    ip_address VARCHAR(45) COMMENT 'IP de origem do token',
    user_agent VARCHAR(255) COMMENT 'User agent do cliente',
    INDEX idx_user_id (user_id),
    INDEX idx_token_hash (token_hash),
    INDEX idx_is_revoked (is_revoked),
    INDEX idx_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabela de refresh tokens';

-- Índice composto para busca rápida
CREATE INDEX idx_user_token ON refresh_tokens(user_id, token_hash, is_revoked);
