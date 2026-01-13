-- ============================================
-- SEED: Dados iniciais para API REST RBAC
-- Descrição: Insere roles e permissões padrão do sistema
-- ============================================

USE api_auth_rbac;

-- ============================================
-- INSERIR PERMISSÕES
-- ============================================
INSERT INTO permissions (name, description, resource, action) VALUES
-- Permissões de Usuário
('USER_CREATE', 'Permite criar novos usuários', 'USER', 'CREATE'),
('USER_READ', 'Permite visualizar usuários', 'USER', 'READ'),
('USER_UPDATE', 'Permite atualizar usuários', 'USER', 'UPDATE'),
('USER_DELETE', 'Permite deletar usuários', 'USER', 'DELETE'),

-- Permissões de Role
('ROLE_CREATE', 'Permite criar novas roles', 'ROLE', 'CREATE'),
('ROLE_READ', 'Permite visualizar roles', 'ROLE', 'READ'),
('ROLE_UPDATE', 'Permite atualizar roles', 'ROLE', 'UPDATE'),
('ROLE_DELETE', 'Permite deletar roles', 'ROLE', 'DELETE'),

-- Permissões de Permissão
('PERMISSION_CREATE', 'Permite criar novas permissões', 'PERMISSION', 'CREATE'),
('PERMISSION_READ', 'Permite visualizar permissões', 'PERMISSION', 'READ'),
('PERMISSION_UPDATE', 'Permite atualizar permissões', 'PERMISSION', 'UPDATE'),
('PERMISSION_DELETE', 'Permite deletar permissões', 'PERMISSION', 'DELETE'),

-- Permissões de Auditoria
('AUDIT_READ', 'Permite visualizar logs de auditoria', 'AUDIT', 'READ')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- ============================================
-- INSERIR ROLES
-- ============================================
INSERT INTO roles (name, description) VALUES
('ADMIN', 'Administrador do sistema com acesso total'),
('MANAGER', 'Gerente com permissões de gerenciamento'),
('USER', 'Usuário padrão com permissões básicas')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- ============================================
-- ASSOCIAR PERMISSÕES ÀS ROLES
-- ============================================

-- ADMIN: Todas as permissões
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'ADMIN'
ON DUPLICATE KEY UPDATE role_id = role_id;

-- MANAGER: Permissões de leitura e atualização (sem delete)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'MANAGER'
AND p.name IN (
    'USER_CREATE', 'USER_READ', 'USER_UPDATE',
    'ROLE_READ',
    'PERMISSION_READ',
    'AUDIT_READ'
)
ON DUPLICATE KEY UPDATE role_id = role_id;

-- USER: Apenas leitura básica
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'USER'
AND p.name IN (
    'USER_READ'
)
ON DUPLICATE KEY UPDATE role_id = role_id;

-- ============================================
-- CRIAR USUÁRIO ADMIN PADRÃO (opcional)
-- Senha padrão: Admin@123 (deve ser alterada em produção)
-- Hash gerado com bcrypt: $2b$10$rOzJqZqZqZqZqZqZqZqZqOeZqZqZqZqZqZqZqZqZqZqZqZqZqZq
-- ============================================
-- Para criar um usuário admin, execute após criar o hash da senha:
-- INSERT INTO users (username, email, password_hash, full_name) VALUES
-- ('admin', 'admin@example.com', '$2b$10$SEU_HASH_AQUI', 'Administrador do Sistema');
-- 
-- INSERT INTO user_roles (user_id, role_id)
-- SELECT u.id, r.id
-- FROM users u, roles r
-- WHERE u.username = 'admin' AND r.name = 'ADMIN';
