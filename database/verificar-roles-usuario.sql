-- ============================================
-- SCRIPT: Verificar Roles de um Usuário
-- ============================================
-- Use para diagnosticar se as roles estão sendo associadas corretamente
-- ============================================

USE api_auth_rbac;

-- ============================================
-- 1. Verificar usuário específico
-- ============================================
-- Substitua 'usuario_teste_1' pelo username que você quer verificar

SELECT 
    u.id,
    u.username,
    u.email,
    u.is_active,
    r.id as role_id,
    r.name as role_name,
    r.description as role_description
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'usuario_teste_1';

-- ============================================
-- 2. Verificar se role USER existe
-- ============================================

SELECT * FROM roles WHERE name = 'USER';

-- ============================================
-- 3. Verificar todos os usuários e suas roles
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
-- 4. Verificar usuários SEM roles
-- ============================================

SELECT 
    u.id,
    u.username,
    u.email,
    u.created_at
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
WHERE ur.user_id IS NULL;

-- ============================================
-- 5. CORREÇÃO: Adicionar role USER a usuário sem roles
-- ============================================
-- Execute apenas se o usuário não tiver roles

-- Verificar ID da role USER
SELECT id, name FROM roles WHERE name = 'USER';

-- Adicionar role USER ao usuário (substitua USER_ID e ROLE_ID)
-- INSERT INTO user_roles (user_id, role_id)
-- VALUES (USER_ID, (SELECT id FROM roles WHERE name = 'USER'));

-- Exemplo para usuário específico:
-- INSERT INTO user_roles (user_id, role_id)
-- SELECT u.id, r.id
-- FROM users u, roles r
-- WHERE u.username = 'usuario_teste_1' AND r.name = 'USER'
-- AND NOT EXISTS (
--     SELECT 1 FROM user_roles ur 
--     WHERE ur.user_id = u.id AND ur.role_id = r.id
-- );

-- ============================================
-- 6. CORREÇÃO: Adicionar role USER a TODOS os usuários sem roles
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
