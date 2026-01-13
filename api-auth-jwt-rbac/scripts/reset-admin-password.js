// ============================================
// SCRIPT: Resetar senha do usuário admin
// ============================================
// 
// Uso: node scripts/reset-admin-password.js
// 
// Este script reseta a senha do usuário admin no banco de dados
// ============================================

const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'api_auth_rbac',
};

const NEW_PASSWORD = 'Admin@123';
const ADMIN_USERNAME = 'admin';

async function resetAdminPassword() {
  console.log('🔧 Resetando senha do usuário admin...\n');

  let connection;

  try {
    // Conectar ao banco
    console.log('1️⃣ Conectando ao MySQL...');
    connection = await mysql.createConnection(DB_CONFIG);
    console.log('✅ Conectado ao MySQL\n');

    // Verificar se usuário existe
    console.log(`2️⃣ Verificando usuário "${ADMIN_USERNAME}"...`);
    const [users] = await connection.execute(
      'SELECT id, username, email, is_active FROM users WHERE username = ?',
      [ADMIN_USERNAME]
    );

    if (users.length === 0) {
      console.log(`❌ Usuário "${ADMIN_USERNAME}" não encontrado!`);
      console.log('\n💡 Opções:');
      console.log('   1. Crie o usuário admin primeiro');
      console.log('   2. Ou use outro username');
      process.exit(1);
    }

    const user = users[0];
    console.log(`✅ Usuário encontrado:`);
    console.log(`   ID: ${user.id}`);
    console.log(`   Username: ${user.username}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Ativo: ${user.is_active ? 'Sim' : 'Não'}\n`);

    // Verificar se está ativo
    if (!user.is_active) {
      console.log('⚠️  Usuário está INATIVO! Ativando...');
      await connection.execute(
        'UPDATE users SET is_active = TRUE WHERE id = ?',
        [user.id]
      );
      console.log('✅ Usuário ativado\n');
    }

    // Gerar hash da nova senha
    console.log('3️⃣ Gerando hash da senha...');
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);
    const passwordHash = await bcrypt.hash(NEW_PASSWORD, saltRounds);
    console.log('✅ Hash gerado\n');

    // Atualizar senha
    console.log('4️⃣ Atualizando senha no banco de dados...');
    await connection.execute(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [passwordHash, user.id]
    );
    console.log('✅ Senha atualizada com sucesso!\n');

    // Verificar role ADMIN
    console.log('5️⃣ Verificando role ADMIN...');
    const [roles] = await connection.execute(
      `SELECT r.id, r.name FROM roles r
       INNER JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ? AND r.name = 'ADMIN'`,
      [user.id]
    );

    if (roles.length === 0) {
      console.log('⚠️  Usuário não tem role ADMIN! Adicionando...');
      const [adminRole] = await connection.execute(
        "SELECT id FROM roles WHERE name = 'ADMIN'"
      );

      if (adminRole.length === 0) {
        console.log('❌ Role ADMIN não encontrada no banco!');
        console.log('   Execute o seed.sql primeiro');
        process.exit(1);
      }

      await connection.execute(
        'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
        [user.id, adminRole[0].id]
      );
      console.log('✅ Role ADMIN adicionada\n');
    } else {
      console.log('✅ Usuário já tem role ADMIN\n');
    }

    // Resumo final
    console.log('═══════════════════════════════════════════════════════');
    console.log('✅ SENHA RESETADA COM SUCESSO!');
    console.log('═══════════════════════════════════════════════════════\n');
    console.log('📋 Credenciais de acesso:');
    console.log(`   Username: ${ADMIN_USERNAME}`);
    console.log(`   Senha: ${NEW_PASSWORD}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Role: ADMIN`);
    console.log(`   Status: Ativo\n`);
    console.log('🔑 Agora você pode fazer login com essas credenciais!');
    console.log('⚠️  IMPORTANTE: Altere a senha após o primeiro login!\n');

  } catch (error) {
    console.error('❌ Erro:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      console.error('\n💡 SOLUÇÃO:');
      console.error('   - Verifique se o MySQL está rodando');
      console.error('   - Verifique as configurações no arquivo .env');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('\n💡 SOLUÇÃO:');
      console.error('   - Verifique DB_USER e DB_PASSWORD no .env');
    } else if (error.code === 'ER_BAD_DB_ERROR') {
      console.error('\n💡 SOLUÇÃO:');
      console.error('   - Execute o schema.sql para criar o banco');
    }
    
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

// Executar
resetAdminPassword();
