-- ============================================
-- SCRIPT: Limpar Usuários de Teste
-- ============================================
-- Use com cuidado! Deleta usuários permanentemente
-- ============================================

USE api_auth_rbac;

-- ============================================
-- OPÇÃO 1: Deletar usuário específico
-- ============================================

-- Ver usuário antes de deletar
SELECT * FROM users WHERE username = 'usuario_teste_1';

-- Deletar relacionamentos primeiro
DELETE FROM user_roles WHERE user_id = (SELECT id FROM users WHERE username = 'usuario_teste_1');
DELETE FROM audit_logs WHERE user_id = (SELECT id FROM users WHERE username = 'usuario_teste_1');

-- Deletar usuário
DELETE FROM users WHERE username = 'usuario_teste_1';

-- ============================================
-- OPÇÃO 2: Deletar todos os usuários de teste
-- ============================================

-- CUIDADO: Isso deleta TODOS os usuários que começam com "usuario_teste"
-- Verifique antes de executar!

-- Ver quais serão deletados
SELECT id, username, email FROM users WHERE username LIKE 'usuario_teste%';

-- Deletar relacionamentos
DELETE ur FROM user_roles ur
INNER JOIN users u ON ur.user_id = u.id
WHERE u.username LIKE 'usuario_teste%';

DELETE al FROM audit_logs al
INNER JOIN users u ON al.user_id = u.id
WHERE u.username LIKE 'usuario_teste%';

-- Deletar usuários
DELETE FROM users WHERE username LIKE 'usuario_teste%';

-- ============================================
-- OPÇÃO 3: Desativar usuários (soft delete)
-- ============================================

-- Desativar usuário específico
UPDATE users SET is_active = FALSE WHERE username = 'usuario_teste_1';

-- Desativar todos os usuários de teste
UPDATE users SET is_active = FALSE WHERE username LIKE 'usuario_teste%';

-- ============================================
-- OPÇÃO 4: Ver todos os usuários
-- ============================================

SELECT 
    id,
    username,
    email,
    full_name,
    is_active,
    created_at
FROM users
ORDER BY created_at DESC;
