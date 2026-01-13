// ============================================
// SCRIPT: Diagnosticar Problema de Login
// ============================================
// 
// Uso: node scripts/diagnosticar-login.js [username]
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

const USERNAME = process.argv[2] || 'admin';

async function diagnosticarLogin() {
  console.log('🔍 Diagnosticando problema de login...\n');
  console.log(`📋 Usuário: ${USERNAME}\n`);

  let connection;

  try {
    // Conectar ao banco
    console.log('1️⃣ Conectando ao MySQL...');
    connection = await mysql.createConnection(DB_CONFIG);
    console.log('✅ Conectado\n');

    // Buscar usuário
    console.log(`2️⃣ Buscando usuário "${USERNAME}"...`);
    const [users] = await connection.execute(
      `SELECT 
        id, 
        username, 
        email, 
        password_hash, 
        is_active,
        LENGTH(password_hash) as hash_length,
        LEFT(password_hash, 7) as hash_start,
        created_at
      FROM users 
      WHERE username = ?`,
      [USERNAME]
    );

    if (users.length === 0) {
      console.log(`❌ Usuário "${USERNAME}" NÃO ENCONTRADO!\n`);
      console.log('💡 Soluções:');
      console.log('   1. Verifique se o username está correto');
      console.log('   2. Crie o usuário via API ou script');
      console.log('   3. Execute: npm run create-admin\n');
      process.exit(1);
    }

    const user = users[0];
    console.log('✅ Usuário encontrado:');
    console.log(`   ID: ${user.id}`);
    console.log(`   Username: ${user.username}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Ativo: ${user.is_active ? '✅ Sim' : '❌ NÃO'}`);
    console.log(`   Hash length: ${user.hash_length} caracteres`);
    console.log(`   Hash start: ${user.hash_start}`);
    console.log(`   Criado em: ${user.created_at}\n`);

    // Verificar problemas
    const problemas = [];

    // Problema 1: Usuário inativo
    if (!user.is_active) {
      problemas.push({
        tipo: 'INATIVO',
        severidade: 'ALTA',
        descricao: 'Usuário está inativo',
        solucao: 'Ativar usuário'
      });
    }

    // Problema 2: Hash incorreto
    if (user.hash_length !== 60) {
      problemas.push({
        tipo: 'HASH_INCORRETO',
        severidade: 'CRÍTICA',
        descricao: `Hash tem ${user.hash_length} caracteres (deveria ter 60)`,
        solucao: 'Corrigir hash da senha'
      });
    }

    // Problema 3: Hash não começa com $2
    if (!user.hash_start.startsWith('$2')) {
      problemas.push({
        tipo: 'HASH_INVALIDO',
        severidade: 'CRÍTICA',
        descricao: `Hash não é bcrypt válido (começa com "${user.hash_start}")`,
        solucao: 'Gerar novo hash bcrypt'
      });
    }

    // Verificar roles
    console.log('3️⃣ Verificando roles...');
    const [roles] = await connection.execute(
      `SELECT r.id, r.name 
       FROM roles r
       INNER JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ?`,
      [user.id]
    );

    if (roles.length === 0) {
      console.log('⚠️  Usuário não tem roles associadas\n');
    } else {
      console.log('✅ Roles encontradas:');
      roles.forEach(r => console.log(`   - ${r.name}`));
      console.log();
    }

    // Mostrar problemas encontrados
    if (problemas.length > 0) {
      console.log('═══════════════════════════════════════════════════════');
      console.log('❌ PROBLEMAS ENCONTRADOS:');
      console.log('═══════════════════════════════════════════════════════\n');
      
      problemas.forEach((p, i) => {
        console.log(`${i + 1}. [${p.severidade}] ${p.tipo}`);
        console.log(`   Descrição: ${p.descricao}`);
        console.log(`   Solução: ${p.solucao}\n`);
      });

      // Oferecer correção automática
      const temHashIncorreto = problemas.some(p => p.tipo.includes('HASH'));
      const temInativo = problemas.some(p => p.tipo === 'INATIVO');

      if (temHashIncorreto || temInativo) {
        console.log('═══════════════════════════════════════════════════════');
        console.log('🔧 CORREÇÃO AUTOMÁTICA DISPONÍVEL');
        console.log('═══════════════════════════════════════════════════════\n');
        console.log('Execute: npm run fix-admin-password\n');
        console.log('Ou corrija manualmente via MySQL Workbench:\n');
        
        if (temHashIncorreto) {
          console.log('1. Gere o hash:');
          console.log('   node -e "const bcrypt = require(\'bcrypt\'); bcrypt.hash(\'Admin@123\', 10).then(hash => console.log(hash));"');
          console.log('\n2. Atualize no MySQL:');
          console.log(`   UPDATE users SET password_hash = 'HASH_AQUI' WHERE username = '${USERNAME}';`);
        }
        
        if (temInativo) {
          console.log(`\n3. Ative o usuário:`);
          console.log(`   UPDATE users SET is_active = TRUE WHERE username = '${USERNAME}';`);
        }
        console.log();
      }
    } else {
      console.log('✅ Nenhum problema encontrado na estrutura do usuário!\n');
      console.log('💡 Possíveis causas:');
      console.log('   1. Senha digitada incorretamente');
      console.log('   2. Username digitado incorretamente');
      console.log('   3. Problema na validação do código\n');
      
      // Testar senha
      console.log('🧪 Teste manual da senha:');
      console.log('   Execute no Node.js:');
      console.log(`   const bcrypt = require('bcrypt');`);
      console.log(`   bcrypt.compare('SUA_SENHA', '${user.password_hash.substring(0, 20)}...').then(r => console.log('Correto?', r));`);
      console.log();
    }

    // Resumo final
    console.log('═══════════════════════════════════════════════════════');
    console.log('📊 RESUMO DO DIAGNÓSTICO');
    console.log('═══════════════════════════════════════════════════════\n');
    console.log(`Usuário: ${user.username}`);
    console.log(`Status: ${user.is_active ? '✅ Ativo' : '❌ Inativo'}`);
    console.log(`Hash: ${user.hash_length === 60 ? '✅ Válido' : '❌ Inválido'} (${user.hash_length} chars)`);
    console.log(`Roles: ${roles.length > 0 ? '✅ ' + roles.map(r => r.name).join(', ') : '❌ Nenhuma'}`);
    console.log(`Problemas encontrados: ${problemas.length}\n`);

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
diagnosticarLogin();
