// ============================================
// TESTS: Autenticação
// ============================================

import request from 'supertest';
import app from '../src/app';
import * as userRepository from '../src/repositories/user.repository';
import * as roleRepository from '../src/repositories/role.repository';
import { hashPassword } from '../src/utils/bcrypt.util';
import { query } from '../src/config/database';
import { User, Role } from '../src/types';

describe('Auth API', () => {
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
      ['testuser', 'test@example.com', passwordHash, 'Test User', true]
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

  describe('POST /api/auth/login', () => {
    it('deve fazer login com credenciais válidas', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'TestPassword123',
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data).toHaveProperty('user');
      expect(response.body.data.user.username).toBe('testuser');
    });

    it('deve retornar 401 com credenciais inválidas', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Credenciais inválidas');
    });

    it('deve retornar 401 com usuário inexistente', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'nonexistent',
          password: 'TestPassword123',
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/auth/me', () => {
    let accessToken!: string;

    beforeAll(async () => {
      // Fazer login para obter token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'TestPassword123',
        });

      accessToken = loginResponse.body.data.accessToken;
    });

    it('deve retornar dados do usuário autenticado', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data).toHaveProperty('username');
      expect(response.body.data.username).toBe('testuser');
    });

    it('deve retornar 401 sem token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('deve retornar 401 com token inválido', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid_token')
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/auth/logout', () => {
    let accessToken!: string;
    let refreshToken!: string;

    beforeAll(async () => {
      // Fazer login para obter tokens
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'TestPassword123',
        });

      accessToken = loginResponse.body.data.accessToken;
      refreshToken = loginResponse.body.data.refreshToken;
    });

    it('deve fazer logout com sucesso', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('deve invalidar token após logout', async () => {
      // Fazer login novamente
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'TestPassword123',
        });

      const newAccessToken = loginResponse.body.data.accessToken;

      // Fazer logout
      await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(200);

      // Tentar usar token revogado
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('revogado');
    });
  });
});
