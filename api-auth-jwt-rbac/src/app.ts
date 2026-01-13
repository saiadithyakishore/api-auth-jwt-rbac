// ============================================
// APP: Configuração principal do Express
// ============================================

import express, { Application } from 'express';
import swaggerUi from 'swagger-ui-express';
import 'express-async-errors';

import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import { errorHandler } from './middlewares/error.middleware';
import { swaggerSpec } from './config/swagger';
import { setupSecurity } from './config/security';

const app: Application = express();

// ============================================
// Configurações globais
// ============================================

// Trust proxy (necessário para rate-limit e logs corretos em produção)
app.set('trust proxy', 1);

// Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ============================================
// Segurança global (ENTERPRISE)
// helmet + cors + rate limit
// ============================================
setupSecurity(app);

// ============================================
// Health check
// ============================================
app.get('/health', (_req, res) => {
  res.json({
    success: true,
    message: 'API está funcionando',
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// Swagger / OpenAPI
// ============================================
app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'API REST RBAC - Documentação',
  })
);

// ============================================
// Rotas da aplicação
// ============================================
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Rotas de debug (apenas em desenvolvimento)
if (process.env.NODE_ENV !== 'production') {
  const debugRoutes = require('./routes/debug.routes').default;
  app.use('/api/debug', debugRoutes);
}

// ============================================
// Rota 404
// ============================================
app.use((_req, res) => {
  res.status(404).json({
    success: false,
    message: 'Rota não encontrada',
  });
});

// ============================================
// Tratamento global de erros (SEMPRE POR ÚLTIMO)
// ============================================
app.use(errorHandler);


export default app;

if (process.env.NODE_ENV !== 'test') {
  console.log('🚀 API RBAC ENTERPRISE SUBIU');
}
