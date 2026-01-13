-- ============================================
-- SCRIPT: Criar usuário administrador inicial
-- Descrição: Script para criar um usuário admin após executar o schema e seed
-- ============================================

USE api_auth_rbac;

-- IMPORTANTE: Substitua 'Admin@123' por uma senha segura antes de executar!
-- Para gerar o hash da senha, você pode usar Node.js:
-- node -e "const bcrypt = require('bcrypt'); bcrypt.hash('Admin@123', 10).then(hash => console.log(hash));"

-- Exemplo de inserção de usuário admin (substitua o hash pela senha gerada)
-- INSERT INTO users (username, email, password_hash, full_name) VALUES
-- ('admin', 'admin@example.com', '$2b$10$SEU_HASH_AQUI', 'Administrador do Sistema');

-- Associar role ADMIN ao usuário criado
-- INSERT INTO user_roles (user_id, role_id)
-- SELECT u.id, r.id
-- FROM users u, roles r
-- WHERE u.username = 'admin' AND r.name = 'ADMIN';

-- ============================================
-- INSTRUÇÕES:
-- 1. Execute o schema.sql para criar as tabelas
-- 2. Execute o seed.sql para popular roles e permissões
-- 3. Gere o hash da senha usando Node.js (comando acima)
-- 4. Execute este script substituindo o hash gerado
-- ============================================
