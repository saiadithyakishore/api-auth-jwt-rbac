-- ============================================
-- SCRIPT: Corrigir Admin Completo
-- ============================================
-- Execute este SQL passo a passo
-- ============================================

USE api_auth_rbac;

-- PASSO 1: Verificar status atual
SELECT 
    id,
    username,
    LENGTH(TRIM(username)) as username_trimmed_length,
    email,
    is_active,
    LENGTH(password_hash) as hash_length,
    LEFT(password_hash, 10) as hash_start
FROM users 
WHERE LOWER(TRIM(username)) = 'admin';

-- PASSO 2: Remover espaços do username (se houver)
UPDATE users 
SET username = TRIM(username) 
WHERE username != TRIM(username);

-- PASSO 3: Gerar hash da senha no terminal:
-- node -e "const bcrypt = require('bcrypt'); bcrypt.hash('Admin@123', 10).then(hash => console.log(hash));"
-- COPIE O HASH GERADO E COLE NO LUGAR DE 'HASH_AQUI' ABAIXO

-- PASSO 4: Atualizar senha e ativar usuário
-- DESCOMENTE E SUBSTITUA HASH_AQUI PELO HASH GERADO:
-- UPDATE users 
-- SET password_hash = 'HASH_AQUI',
--     is_active = TRUE
-- WHERE LOWER(TRIM(username)) = 'admin';

-- PASSO 5: Verificar role ADMIN
SELECT 
    u.id,
    u.username,
    r.name as role
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE LOWER(TRIM(u.username)) = 'admin';

-- PASSO 6: Adicionar role ADMIN se não tiver
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE LOWER(TRIM(u.username)) = 'admin' AND r.name = 'ADMIN'
AND NOT EXISTS (
    SELECT 1 FROM user_roles ur 
    WHERE ur.user_id = u.id AND ur.role_id = r.id
);

-- PASSO 7: Verificação final
SELECT 
    u.id,
    u.username,
    u.email,
    u.is_active,
    LENGTH(u.password_hash) as hash_length,
    GROUP_CONCAT(r.name) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE LOWER(TRIM(u.username)) = 'admin'
GROUP BY u.id;

-- RESULTADO ESPERADO:
-- hash_length: 60
-- is_active: 1
-- roles: ADMIN
