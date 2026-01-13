// ============================================
// SERVER: Inicialização do servidor
// ============================================

import dotenv from 'dotenv';
import app from './app';
import { testConnection } from './config/database';

dotenv.config();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Função para inicializar o servidor
async function startServer(): Promise<void> {
  try {
    // Testar conexão com banco de dados
    await testConnection();

    // Iniciar servidor
    app.listen(PORT, () => {
      console.log('===========================================');
      console.log('🚀 Servidor iniciado com sucesso!');
      console.log(`📍 Ambiente: ${NODE_ENV}`);
      console.log(`🌐 Porta: ${PORT}`);
      console.log(`🔗 URL: http://localhost:${PORT}`);
      console.log('===========================================');
    });
  } catch (error) {
    console.error('❌ Erro ao iniciar servidor:', error);
    process.exit(1);
  }
}

// Inicializar servidor
startServer();

// Tratamento de erros não capturados
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});
