-- ============================================
-- SCRIPT: Correção Completa - Usuários e Roles
-- ============================================
-- Execute este script para corrigir TUDO de uma vez
-- ============================================

USE api_auth_rbac;

-- ============================================
-- PASSO 1: Verificar usuários sem roles
-- ============================================

SELECT 
    u.id,
    u.username,
    u.email,
    COUNT(ur.role_id) as role_count
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
GROUP BY u.id, u.username, u.email
HAVING role_count = 0;

-- ============================================
-- PASSO 2: Verificar se role USER existe
-- ============================================

SELECT id, name FROM roles WHERE name = 'USER';

-- Se não existir, execute: database/seed.sql primeiro!

-- ============================================
-- PASSO 3: CORRIGIR - Adicionar role USER a todos os usuários sem roles
-- ============================================

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE r.name = 'USER'
AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
);

-- ============================================
-- PASSO 4: Verificar resultado
-- ============================================

SELECT 
    u.id,
    u.username,
    u.email,
    GROUP_CONCAT(r.name) as roles,
    COUNT(r.id) as role_count
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
GROUP BY u.id, u.username, u.email
ORDER BY u.created_at DESC;

-- ============================================
-- RESULTADO ESPERADO:
-- Todos os usuários devem ter pelo menos "USER" na coluna roles
-- role_count deve ser >= 1 para todos
-- ============================================
