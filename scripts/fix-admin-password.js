// ============================================
// SCRIPT: Corrigir hash da senha do admin
// ============================================
// 
// Uso: node scripts/fix-admin-password.js
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

async function fixAdminPassword() {
  console.log('🔧 Corrigindo hash da senha do admin...\n');

  let connection;

  try {
    // Conectar ao banco
    console.log('1️⃣ Conectando ao MySQL...');
    connection = await mysql.createConnection(DB_CONFIG);
    console.log('✅ Conectado\n');

    // Verificar usuário
    console.log(`2️⃣ Verificando usuário "${ADMIN_USERNAME}"...`);
    const [users] = await connection.execute(
      'SELECT id, username, email, password_hash, is_active, LENGTH(password_hash) as hash_len FROM users WHERE username = ?',
      [ADMIN_USERNAME]
    );

    if (users.length === 0) {
      console.log(`❌ Usuário "${ADMIN_USERNAME}" não encontrado!`);
      process.exit(1);
    }

    const user = users[0];
    console.log(`✅ Usuário encontrado:`);
    console.log(`   ID: ${user.id}`);
    console.log(`   Username: ${user.username}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Hash atual: ${user.hash_len} caracteres (deveria ser 60)`);
    console.log(`   Ativo: ${user.is_active ? 'Sim' : 'Não'}\n`);

    // Gerar hash correto
    console.log('3️⃣ Gerando hash bcrypt correto...');
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);
    const passwordHash = await bcrypt.hash(NEW_PASSWORD, saltRounds);
    console.log(`✅ Hash gerado: ${passwordHash.length} caracteres`);
    console.log(`   Hash: ${passwordHash.substring(0, 20)}...\n`);

    // Atualizar senha e ativar
    console.log('4️⃣ Atualizando senha no banco...');
    await connection.execute(
      'UPDATE users SET password_hash = ?, is_active = TRUE WHERE id = ?',
      [passwordHash, user.id]
    );
    console.log('✅ Senha atualizada e usuário ativado!\n');

    // Verificar role ADMIN
    console.log('5️⃣ Verificando role ADMIN...');
    const [roles] = await connection.execute(
      `SELECT r.id, r.name FROM roles r
       INNER JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ? AND r.name = 'ADMIN'`,
      [user.id]
    );

    if (roles.length === 0) {
      console.log('⚠️  Adicionando role ADMIN...');
      const [adminRole] = await connection.execute(
        "SELECT id FROM roles WHERE name = 'ADMIN'"
      );

      if (adminRole.length === 0) {
        console.log('❌ Role ADMIN não encontrada! Execute seed.sql primeiro.');
        process.exit(1);
      }

      await connection.execute(
        'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
        [user.id, adminRole[0].id]
      );
      console.log('✅ Role ADMIN adicionada!\n');
    } else {
      console.log('✅ Usuário já tem role ADMIN\n');
    }

    // Verificar resultado
    console.log('6️⃣ Verificando correção...');
    const [updated] = await connection.execute(
      'SELECT username, is_active, LENGTH(password_hash) as hash_len FROM users WHERE id = ?',
      [user.id]
    );
    
    const updatedUser = updated[0];
    console.log(`✅ Verificação:`);
    console.log(`   Hash: ${updatedUser.hash_len} caracteres ${updatedUser.hash_len === 60 ? '✅' : '❌'}`);
    console.log(`   Ativo: ${updatedUser.is_active ? 'Sim ✅' : 'Não ❌'}\n`);

    // Resumo final
    console.log('═══════════════════════════════════════════════════════');
    console.log('✅ SENHA CORRIGIDA COM SUCESSO!');
    console.log('═══════════════════════════════════════════════════════\n');
    console.log('📋 Credenciais de acesso:');
    console.log(`   Username: ${ADMIN_USERNAME}`);
    console.log(`   Senha: ${NEW_PASSWORD}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Role: ADMIN`);
    console.log(`   Status: Ativo\n`);
    console.log('🔑 Agora você pode fazer login!');
    console.log('⚠️  IMPORTANTE: Altere a senha após o primeiro login!\n');

  } catch (error) {
    console.error('❌ Erro:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      console.error('\n💡 MySQL não está rodando!');
      console.error('   Inicie o MySQL e tente novamente.');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('\n💡 Credenciais do MySQL incorretas!');
      console.error('   Verifique DB_USER e DB_PASSWORD no .env');
    } else if (error.code === 'ER_BAD_DB_ERROR') {
      console.error('\n💡 Banco de dados não existe!');
      console.error('   Execute database/schema.sql primeiro');
    }
    
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

// Executar
fixAdminPassword();
