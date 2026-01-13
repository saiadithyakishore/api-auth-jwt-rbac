// ============================================
// SCRIPT: Criar usuário admin usando token JWT
// ============================================
// 
// Uso: node scripts/create-admin-with-token.js
// ============================================

const http = require('http');

const API_URL = 'http://localhost:3000';
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoiam9hbyB2aXRvciIsImVtYWlsIjoiam9hb3ZtcDM5Z21haWwuY29tIiwicm9sZXMiOlsiQURNSU4iXSwiaWF0IjoxNzY4MjM3MDQ3LCJleHAiOjE3NjgzMjM0NDd9.yyEeM9ON7wydu0Wn6TY_DczQB6Cn-QZ07yF6VfgZUeQ';

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
  console.log(`📋 Dados do admin:`);
  console.log(`   Username: ${ADMIN_DATA.username}`);
  console.log(`   Email: ${ADMIN_DATA.email}`);
  console.log(`   Senha: ${ADMIN_DATA.password}`);
  console.log(`   Role: ADMIN (ID: ${ADMIN_DATA.roleIds[0]})\n`);

  try {
    // Verificar se API está rodando
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

    // Criar usuário admin
    console.log('2️⃣ Criando usuário admin...');
    const createOptions = {
      hostname: 'localhost',
      port: 3000,
      path: '/api/users',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TOKEN}`
      }
    };

    const result = await makeRequest(createOptions, ADMIN_DATA);

    if (result.status === 201) {
      console.log('✅ Usuário admin criado com sucesso!\n');
      console.log('📋 Informações do usuário criado:');
      console.log(`   ID: ${result.data.data.id}`);
      console.log(`   Username: ${result.data.data.username}`);
      console.log(`   Email: ${result.data.data.email}`);
      console.log(`   Nome: ${result.data.data.fullName}`);
      console.log(`   Roles: ${result.data.data.roles.map(r => r.name).join(', ')}\n`);
      console.log('🔑 Credenciais de acesso:');
      console.log(`   Username: ${ADMIN_DATA.username}`);
      console.log(`   Senha: ${ADMIN_DATA.password}\n`);
      console.log('⚠️  IMPORTANTE: Altere a senha após o primeiro login!\n');
      console.log('✅ Pronto! Agora você pode fazer login com o usuário admin.');
    } else if (result.status === 409) {
      console.log('⚠️  Usuário admin já existe!');
      console.log('\n💡 Opções:');
      console.log('   1. Use outro username/email');
      console.log('   2. Ou atualize o usuário existente para ter role ADMIN');
    } else if (result.status === 401) {
      console.error('❌ Token inválido ou expirado!');
      console.error('   Gere um novo token fazendo login novamente.');
    } else if (result.status === 403) {
      console.error('❌ Acesso negado!');
      console.error('   Você precisa da permissão USER_CREATE para criar usuários.');
      console.error('   Verifique se seu usuário tem a role ADMIN ou MANAGER.');
    } else {
      console.error('❌ Erro ao criar usuário:', result.data);
      console.error(`   Status: ${result.status}`);
    }

    process.exit(result.status === 201 ? 0 : 1);
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
