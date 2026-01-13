// ============================================
// TESTS: Refresh Token
// ============================================

import request from 'supertest';
import app from '../src/app';
import * as userRepository from '../src/repositories/user.repository';
import * as roleRepository from '../src/repositories/role.repository';
import { hashPassword } from '../src/utils/bcrypt.util';
import { query } from '../src/config/database';
import { User, Role } from '../src/types';

describe('Refresh Token API', () => {
  let testUser: User | null;
  let testRole: Role | null;

  beforeAll(async () => {
    // Criar role de teste
    const roleResult = await query(
      'INSERT INTO roles (name, description) VALUES (?, ?)',
      ['TEST_USER', 'Role para testes']
    );
    testRole = await roleRepository.findById(roleResult.insertId);

    // Criar usuário de teste
    const passwordHash = await hashPassword('TestPassword123');
    const userResult = await query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active) 
       VALUES (?, ?, ?, ?, ?)`,
      ['refreshtest', 'refresh@test.com', passwordHash, 'Refresh Test', true]
    );
    testUser = await userRepository.findById(userResult.insertId);

    // Associar role ao usuário
    if (!testUser || !testRole) {
      throw new Error('Falha ao criar dados de teste');
    }
    await query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [testUser.id, testRole.id]
    );
  });

  afterAll(async () => {
    // Limpar dados de teste
    if (testUser && testUser.id) {
      await query('DELETE FROM user_roles WHERE user_id = ?', [testUser.id]);
      await query('DELETE FROM users WHERE id = ?', [testUser.id]);
    }
    if (testRole && testRole.id) {
      await query('DELETE FROM roles WHERE id = ?', [testRole.id]);
    }
  });

  describe('POST /api/auth/refresh-token', () => {
    it('deve renovar access token com refresh token válido', async () => {
      // 1. Fazer login
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'refreshtest',
          password: 'TestPassword123',
        })
        .expect(200);

      const refreshToken = loginResponse.body.data.refreshToken;

      // 2. Renovar token
      const refreshResponse = await request(app)
        .post('/api/auth/refresh-token')
        .send({
          refreshToken,
        })
        .expect(200);

      expect(refreshResponse.body.success).toBe(true);
      expect(refreshResponse.body.data).toHaveProperty('accessToken');
      expect(refreshResponse.body.data).toHaveProperty('refreshToken');
      
      // Novo refresh token deve ser diferente do antigo
      expect(refreshResponse.body.data.refreshToken).not.toBe(refreshToken);
    });

    it('deve retornar 401 com refresh token inválido', async () => {
      const response = await request(app)
        .post('/api/auth/refresh-token')
        .send({
          refreshToken: 'invalid_refresh_token',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('deve invalidar refresh token antigo após rotação', async () => {
      // 1. Fazer login
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'refreshtest',
          password: 'TestPassword123',
        });

      const oldRefreshToken = loginResponse.body.data.refreshToken;

      // 2. Renovar token (rotação)
      await request(app)
        .post('/api/auth/refresh-token')
        .send({
          refreshToken: oldRefreshToken,
        })
        .expect(200);

      // 3. Tentar usar refresh token antigo (deve falhar)
      const response = await request(app)
        .post('/api/auth/refresh-token')
        .send({
          refreshToken: oldRefreshToken,
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });
});
