-- ============================================
-- SCRIPT: Corrigir Usuários Sem Roles
-- ============================================
-- Adiciona role USER a todos os usuários que não têm roles
-- ============================================

USE api_auth_rbac;

-- ============================================
-- 1. VERIFICAR: Usuários sem roles
-- ============================================

SELECT 
    u.id,
    u.username,
    u.email,
    u.created_at,
    COUNT(ur.role_id) as role_count
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
GROUP BY u.id, u.username, u.email, u.created_at
HAVING role_count = 0
ORDER BY u.created_at DESC;

-- ============================================
-- 2. VERIFICAR: Se role USER existe
-- ============================================

SELECT id, name, description FROM roles WHERE name = 'USER';

-- Se não existir, execute o seed.sql primeiro!

-- ============================================
-- 3. CORRIGIR: Adicionar role USER a todos os usuários sem roles
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
-- 4. VERIFICAR: Resultado após correção
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

-- Todos os usuários devem ter pelo menos a role USER agora!
