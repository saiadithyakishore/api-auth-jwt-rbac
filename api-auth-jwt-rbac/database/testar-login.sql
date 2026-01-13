-- ============================================
-- SCRIPT: Testar Login Manualmente
-- ============================================
-- Execute este SQL para verificar o usuário exato
-- ============================================

USE api_auth_rbac;

-- 1. Ver TODOS os usuários com detalhes
SELECT 
    id,
    username,
    LENGTH(username) as username_length,
    ASCII(LEFT(username, 1)) as first_char_code,
    email,
    is_active,
    LENGTH(password_hash) as hash_length,
    LEFT(password_hash, 10) as hash_start
FROM users;

-- 2. Verificar se há espaços no username
SELECT 
    username,
    LENGTH(username) as length,
    LENGTH(TRIM(username)) as trimmed_length,
    CONCAT('|', username, '|') as with_pipes
FROM users
WHERE username LIKE '% %' OR username LIKE ' %' OR username LIKE '% ';

-- 3. Buscar usuário admin (case-insensitive)
SELECT 
    id,
    username,
    email,
    is_active,
    LENGTH(password_hash) as hash_length
FROM users 
WHERE LOWER(TRIM(username)) = LOWER(TRIM('admin'));

-- 4. Verificar hash bcrypt manualmente
-- Pegue o hash completo do SELECT acima e teste no Node.js:
-- node -e "const bcrypt = require('bcrypt'); bcrypt.compare('Admin@123', 'HASH_DO_BANCO').then(r => console.log('Senha correta?', r));"

-- 5. CORREÇÃO: Se o username tiver espaços, remova-os
-- UPDATE users SET username = TRIM(username) WHERE username != TRIM(username);

-- 6. CORREÇÃO: Se precisar resetar a senha
-- Gere o hash: node -e "const bcrypt = require('bcrypt'); bcrypt.hash('Admin@123', 10).then(hash => console.log(hash));"
-- UPDATE users 
-- SET password_hash = 'HASH_GERADO_AQUI',
--     is_active = TRUE
-- WHERE LOWER(TRIM(username)) = 'admin';
