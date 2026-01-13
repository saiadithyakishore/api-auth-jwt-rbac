// ============================================
// SCRIPT: Criar usuário administrador via API
// ============================================
// 
// Uso: node scripts/create-admin-user.js
// 
// Este script cria um usuário admin usando a API
// Você precisa ter pelo menos um usuário criado primeiro
// ============================================

const http = require('http');

const API_URL = 'http://localhost:3000';
const ADMIN_DATA = {
  username: 'admin',
  email: 'admin@example.com',
  password: 'Admin@123',
  fullName: 'Administrador do Sistema',
  roleIds: [1] // 1 = ADMIN (verifique no banco se necessário)
};

// Função para fazer requisição HTTP
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, data: body });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

async function createAdmin() {
  console.log('🚀 Criando usuário administrador...\n');

  try {
    // Passo 1: Verificar se API está rodando
    console.log('1️⃣ Verificando se API está rodando...');
    const healthCheck = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/health',
      method: 'GET'
    });

    if (healthCheck.status !== 200) {
      console.error('❌ API não está respondendo corretamente');
      process.exit(1);
    }
    console.log('✅ API está funcionando\n');

    // Passo 2: Registrar usuário admin
    console.log('2️⃣ Registrando usuário admin...');
    const registerOptions = {
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const registerResult = await makeRequest(registerOptions, ADMIN_DATA);

    if (registerResult.status === 201) {
      console.log('✅ Usuário admin criado com sucesso!');
      console.log('\n📋 Credenciais:');
      console.log(`   Username: ${ADMIN_DATA.username}`);
      console.log(`   Email: ${ADMIN_DATA.email}`);
      console.log(`   Senha: ${ADMIN_DATA.password}`);
      console.log('\n⚠️  IMPORTANTE: Altere a senha após o primeiro login!');
      
      // Se o registro retornou token, mostrar
      if (registerResult.data.data && registerResult.data.data.token) {
        console.log('\n🔑 Token JWT gerado (use para testes):');
        console.log(`   ${registerResult.data.data.token.substring(0, 50)}...`);
      }

      // Nota sobre roles
      console.log('\n💡 Nota: O usuário foi criado sem roles.');
      console.log('   Para adicionar role ADMIN, você precisa:');
      console.log('   1. Fazer login com este usuário');
      console.log('   2. Usar o token para atualizar o usuário via API');
      console.log('   3. Ou adicionar manualmente no MySQL Workbench');
      
      process.exit(0);
    } else if (registerResult.status === 409) {
      console.log('⚠️  Usuário admin já existe!');
      console.log('\n📋 Credenciais existentes:');
      console.log(`   Username: ${ADMIN_DATA.username}`);
      console.log(`   Email: ${ADMIN_DATA.email}`);
      console.log(`   Senha: ${ADMIN_DATA.password}`);
      console.log('\n💡 Se não lembra a senha, você pode:');
      console.log('   1. Resetar no MySQL Workbench');
      console.log('   2. Ou deletar e recriar o usuário');
      process.exit(0);
    } else {
      console.error('❌ Erro ao criar usuário:', registerResult.data);
      process.exit(1);
    }
  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      console.error('❌ Erro: Não foi possível conectar à API');
      console.error('   Certifique-se de que o servidor está rodando:');
      console.error('   Execute: npm run dev');
    } else {
      console.error('❌ Erro:', error.message);
    }
    process.exit(1);
  }
}

// Executar
createAdmin();
