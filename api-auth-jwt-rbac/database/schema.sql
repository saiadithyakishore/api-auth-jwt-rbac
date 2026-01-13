-- ============================================
-- SCHEMA: API REST - Autenticação e Autorização RBAC
-- Descrição: Estrutura completa do banco de dados para sistema RBAC
-- ============================================

-- Criar banco de dados
CREATE DATABASE IF NOT EXISTS api_auth_rbac CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE api_auth_rbac;

-- ============================================
-- TABELA: users
-- Descrição: Armazena informações dos usuários do sistema
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE COMMENT 'Nome de usuário único',
    email VARCHAR(100) NOT NULL UNIQUE COMMENT 'Email único do usuário',
    password_hash VARCHAR(255) NOT NULL COMMENT 'Hash da senha usando bcrypt',
    full_name VARCHAR(100) NOT NULL COMMENT 'Nome completo do usuário',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Flag para ativar/desativar usuário',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de criação',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Data de atualização',
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabela de usuários';

-- ============================================
-- TABELA: roles
-- Descrição: Armazena as roles (papéis) do sistema
-- ============================================
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE COMMENT 'Nome da role (ex: ADMIN, MANAGER, USER)',
    description VARCHAR(255) COMMENT 'Descrição da role',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de criação',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Data de atualização',
    INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabela de roles';

-- ============================================
-- TABELA: permissions
-- Descrição: Armazena as permissões granulares do sistema
-- ============================================
CREATE TABLE IF NOT EXISTS permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Nome da permissão (ex: USER_CREATE, USER_READ)',
    description VARCHAR(255) COMMENT 'Descrição da permissão',
    resource VARCHAR(50) NOT NULL COMMENT 'Recurso relacionado (ex: USER, ROLE, PERMISSION)',
    action VARCHAR(50) NOT NULL COMMENT 'Ação permitida (ex: CREATE, READ, UPDATE, DELETE)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de criação',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Data de atualização',
    INDEX idx_name (name),
    INDEX idx_resource (resource),
    INDEX idx_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tabela de permissões';

-- ============================================
-- TABELA: user_roles (Relacionamento N:N)
-- Descrição: Relaciona usuários com suas roles
-- ============================================
CREATE TABLE IF NOT EXISTS user_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL COMMENT 'ID do usuário',
    role_id INT NOT NULL COMMENT 'ID da role',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de criação',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_role (user_id, role_id),
    INDEX idx_user_id (user_id),
    INDEX idx_role_id (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Relacionamento usuário-role';

-- ============================================
-- TABELA: role_permissions (Relacionamento N:N)
-- Descrição: Relaciona roles com suas permissões
-- ============================================
CREATE TABLE IF NOT EXISTS role_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_id INT NOT NULL COMMENT 'ID da role',
    permission_id INT NOT NULL COMMENT 'ID da permissão',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de criação',
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE KEY unique_role_permission (role_id, permission_id),
    INDEX idx_role_id (role_id),
    INDEX idx_permission_id (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Relacionamento role-permissão';

-- ============================================
-- TABELA: audit_logs (Opcional - para registro de ações)
-- Descrição: Registra ações sensíveis do sistema
-- ============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT COMMENT 'ID do usuário que realizou a ação',
    action VARCHAR(100) NOT NULL COMMENT 'Ação realizada (ex: USER_CREATED, USER_DELETED)',
    resource_type VARCHAR(50) COMMENT 'Tipo de recurso afetado',
    resource_id INT COMMENT 'ID do recurso afetado',
    details JSON COMMENT 'Detalhes adicionais em formato JSON',
    ip_address VARCHAR(45) COMMENT 'Endereço IP de origem',
    user_agent VARCHAR(255) COMMENT 'User agent do cliente',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data da ação',
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_resource_type (resource_type),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Log de auditoria';
