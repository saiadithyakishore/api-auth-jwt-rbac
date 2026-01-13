// ============================================
// SCRIPT: Criar arquivo .env a partir do template
// ============================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Gerar JWT_SECRET aleatório
const generateJWTSecret = () => {
  return crypto.randomBytes(64).toString('hex');
};

// Template do .env
const envTemplate = `# ============================================
# CONFIGURAÇÕES DE AMBIENTE - API REST RBAC
# ============================================
# Arquivo gerado automaticamente em ${new Date().toLocaleString('pt-BR')}
# ============================================

# ============================================
# SERVIDOR
# ============================================
PORT=3000
NODE_ENV=development

# ============================================
# BANCO DE DADOS MYSQL
# ============================================
# Host do MySQL (geralmente localhost)
DB_HOST=localhost

# Porta do MySQL (padrão: 3306)
DB_PORT=3306

# Usuário do MySQL (geralmente root)
DB_USER=root

# Senha do MySQL (ALTERE AQUI com sua senha!)
DB_PASSWORD=

# Nome do banco de dados
DB_NAME=api_auth_rbac

# ============================================
# JWT (JSON WEB TOKEN)
# ============================================
# SECRET gerado automaticamente (pode ser alterado)
JWT_SECRET=${generateJWTSecret()}

# Tempo de expiração do token (ex: 24h, 7d, 30d)
JWT_EXPIRES_IN=24h

# ============================================
# SEGURANÇA
# ============================================
# Número de rounds do bcrypt (padrão: 10)
BCRYPT_ROUNDS=10
`;

// Caminho do arquivo .env
const envPath = path.join(__dirname, '.env');

// Verificar se .env já existe
if (fs.existsSync(envPath)) {
  console.log('⚠️  Arquivo .env já existe!');
  console.log('   Se deseja recriar, delete o arquivo .env primeiro.');
  process.exit(0);
}

// Criar arquivo .env
try {
  fs.writeFileSync(envPath, envTemplate, 'utf8');
  console.log('✅ Arquivo .env criado com sucesso!');
  console.log('');
  console.log('📝 PRÓXIMOS PASSOS:');
  console.log('   1. Abra o arquivo .env');
  console.log('   2. Configure DB_PASSWORD com sua senha do MySQL');
  console.log('   3. Ajuste outras configurações se necessário');
  console.log('');
  console.log('⚠️  IMPORTANTE:');
  console.log('   - O JWT_SECRET foi gerado automaticamente');
  console.log('   - NUNCA compartilhe ou commite o arquivo .env');
  console.log('');
} catch (error) {
  console.error('❌ Erro ao criar arquivo .env:', error.message);
  process.exit(1);
}
