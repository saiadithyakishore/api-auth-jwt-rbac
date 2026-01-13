-- ============================================
-- SCRIPT: Diagnosticar Problema de Login
-- ============================================
-- Execute este SQL no MySQL Workbench
-- ============================================

USE api_auth_rbac;

-- 1. Verificar usuário admin
SELECT 
    id,
    username,
    email,
    is_active,
    LENGTH(password_hash) as hash_length,
    LEFT(password_hash, 7) as hash_start,
    created_at
FROM users 
WHERE username = 'admin';

-- 2. Verificar roles do admin
SELECT 
    u.username,
    r.name as role,
    r.id as role_id
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'admin';

-- 3. Verificar todos os usuários (para ver qual username usar)
SELECT 
    id,
    username,
    email,
    is_active,
    LENGTH(password_hash) as hash_length
FROM users;

-- ============================================
-- CORREÇÕES (Execute apenas se necessário)
-- ============================================

-- CORREÇÃO 1: Se o hash tiver menos de 60 caracteres
-- Primeiro, gere o hash no terminal do projeto:
-- node -e "const bcrypt = require('bcrypt'); bcrypt.hash('Admin@123', 10).then(hash => console.log(hash));"
-- Depois, substitua HASH_AQUI pelo hash gerado:

-- UPDATE users 
-- SET password_hash = 'HASH_AQUI',
--     is_active = TRUE
-- WHERE username = 'admin';

-- CORREÇÃO 2: Se o usuário estiver inativo
-- UPDATE users 
-- SET is_active = TRUE 
-- WHERE username = 'admin';

-- CORREÇÃO 3: Se não tiver role ADMIN
-- INSERT INTO user_roles (user_id, role_id)
-- SELECT u.id, r.id
-- FROM users u, roles r
-- WHERE u.username = 'admin' AND r.name = 'ADMIN'
-- AND NOT EXISTS (
--     SELECT 1 FROM user_roles ur 
--     WHERE ur.user_id = u.id AND ur.role_id = r.id
-- );
