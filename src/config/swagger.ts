// ============================================
// CONFIGURAÇÃO: Swagger/OpenAPI
// ============================================
// 
// Documentação automática da API
// Acesse em: http://localhost:3000/api-docs
// ============================================

import swaggerJsdoc from 'swagger-jsdoc';
import { SwaggerDefinition } from 'swagger-jsdoc';

const swaggerDefinition: SwaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API REST - Autenticação e Autorização RBAC',
    version: '1.0.0',
    description: `
      API REST profissional de Autenticação e Autorização utilizando **Role-Based Access Control (RBAC)**.
      
      ## Características
      - ✅ Autenticação JWT com Access Token
      - ✅ RBAC completo com roles e permissões granulares
      - ✅ Sistema de auditoria
      - ✅ Validações robustas
      - ✅ Logs estruturados
      
      ## Autenticação
      Após fazer login, use o token no header:
      \`\`\`
      Authorization: Bearer <seu_token>
      \`\`\`
      
      ## Roles Padrão
      - **ADMIN**: Acesso total
      - **MANAGER**: Gerenciamento (sem delete)
      - **USER**: Permissões básicas
    `,
    contact: {
      name: 'API Support',
    },
    license: {
      name: 'ISC',
    },
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Servidor de desenvolvimento',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Token JWT obtido via /api/auth/login',
      },
    },
    schemas: {
      RegisterRequest: {
        type: 'object',
        required: ['username', 'email', 'password', 'fullName'],
        properties: {
          username: {
            type: 'string',
            minLength: 3,
            maxLength: 20,
            pattern: '^[a-zA-Z0-9_]+$',
            example: 'johndoe',
            description: 'Username único (3-20 caracteres, apenas letras, números e _)',
          },
          email: {
            type: 'string',
            format: 'email',
            maxLength: 100,
            example: 'john@example.com',
          },
          password: {
            type: 'string',
            minLength: 6,
            maxLength: 100,
            example: 'senha123',
            description: 'Mínimo 6 caracteres, deve conter letras e números',
          },
          fullName: {
            type: 'string',
            minLength: 2,
            maxLength: 100,
            example: 'John Doe',
          },
        },
      },
      LoginRequest: {
        type: 'object',
        required: ['username', 'password'],
        properties: {
          username: {
            type: 'string',
            example: 'johndoe',
          },
          password: {
            type: 'string',
            example: 'senha123',
          },
        },
      },
      AuthResponse: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: true,
          },
          message: {
            type: 'string',
            example: 'Login realizado com sucesso',
          },
          data: {
            type: 'object',
            properties: {
              token: {
                type: 'string',
                example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                description: 'JWT Access Token (expira em 15 minutos)',
              },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'number', example: 1 },
                  username: { type: 'string', example: 'johndoe' },
                  email: { type: 'string', example: 'john@example.com' },
                  fullName: { type: 'string', example: 'John Doe' },
                  roles: {
                    type: 'array',
                    items: { type: 'string' },
                    example: ['USER'],
                    description: 'Array de roles do usuário',
                  },
                },
              },
            },
          },
        },
      },
      UpdateRolesRequest: {
        type: 'object',
        required: ['roleIds'],
        properties: {
          roleIds: {
            type: 'array',
            items: { type: 'number' },
            minItems: 1,
            maxItems: 10,
            example: [1, 2],
            description: 'Array de IDs das roles a serem atribuídas',
          },
        },
      },
      ApiResponse: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: true,
          },
          message: {
            type: 'string',
            example: 'Operação realizada com sucesso',
          },
          data: {
            type: 'object',
            description: 'Dados da resposta (varia conforme endpoint)',
          },
          error: {
            type: 'string',
            description: 'Detalhes do erro (apenas em desenvolvimento)',
          },
        },
      },
    },
  },
  tags: [
    {
      name: 'Autenticação',
      description: 'Endpoints de registro, login e informações do usuário',
    },
    {
      name: 'Usuários',
      description: 'Gerenciamento de usuários (requer autenticação)',
    },
    {
      name: 'Roles',
      description: 'Gerenciamento de roles (requer role ADMIN)',
    },
  ],
};

const options = {
  definition: swaggerDefinition,
  apis: ['./src/routes/*.ts', './src/controllers/*.ts'], // Caminhos para arquivos com anotações
};

export const swaggerSpec = swaggerJsdoc(options);
