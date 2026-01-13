// ============================================
// TESTS: RBAC (Role-Based Access Control)
// ============================================

import request from 'supertest';
import app from '../src/app';
import * as userRepository from '../src/repositories/user.repository';
import * as roleRepository from '../src/repositories/role.repository';
import { hashPassword } from '../src/utils/bcrypt.util';
import { query } from '../src/config/database';
import { User, Role } from '../src/types';

describe('RBAC API', () => {
  let adminUser: User | null;
  let regularUser: User | null;
  let adminRole: Role | null;
  let userRole: Role | null;

  beforeAll(async () => {
    // Criar roles
    const adminRoleResult = await query(
      'INSERT INTO roles (name, description) VALUES (?, ?)',
      ['ADMIN', 'Administrador']
    );
    adminRole = await roleRepository.findById(adminRoleResult.insertId);

    const userRoleResult = await query(
      'INSERT INTO roles (name, description) VALUES (?, ?)',
      ['USER', 'Usuário comum']
    );
    userRole = await roleRepository.findById(userRoleResult.insertId);

    // Criar usuário ADMIN
    const adminPasswordHash = await hashPassword('Admin123');
    const adminResult = await query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active) 
       VALUES (?, ?, ?, ?, ?)`,
      ['admin_test', 'admin@test.com', adminPasswordHash, 'Admin Test', true]
    );
    adminUser = await userRepository.findById(adminResult.insertId);
    if (!adminUser || !adminRole) {
      throw new Error('Falha ao criar dados de teste (admin)');
    }
    await query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [adminUser.id, adminRole.id]
    );

    // Criar usuário comum
    const userPasswordHash = await hashPassword('User123');
    const userResult = await query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active) 
       VALUES (?, ?, ?, ?, ?)`,
      ['user_test', 'user@test.com', userPasswordHash, 'User Test', true]
    );
    regularUser = await userRepository.findById(userResult.insertId);
    if (!regularUser || !userRole) {
      throw new Error('Falha ao criar dados de teste (user)');
    }
    await query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [regularUser.id, userRole.id]
    );
  });

  afterAll(async () => {
    // Limpar dados de teste
    if (adminUser && adminUser.id) {
      await query('DELETE FROM user_roles WHERE user_id = ?', [adminUser.id]);
      await query('DELETE FROM users WHERE id = ?', [adminUser.id]);
    }
    if (regularUser && regularUser.id) {
      await query('DELETE FROM user_roles WHERE user_id = ?', [regularUser.id]);
      await query('DELETE FROM users WHERE id = ?', [regularUser.id]);
    }
    if (adminRole && adminRole.id) {
      await query('DELETE FROM roles WHERE id = ?', [adminRole.id]);
    }
    if (userRole && userRole.id) {
      await query('DELETE FROM roles WHERE id = ?', [userRole.id]);
    }
  });

  describe('PUT /api/users/:id/roles', () => {
    let adminToken!: string;
    let userToken!: string;

    beforeAll(async () => {
      // Login como ADMIN
      const adminLogin = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'admin_test',
          password: 'Admin123',
        });
      adminToken = adminLogin.body.data.accessToken;

      // Login como USER
      const userLogin = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'user_test',
          password: 'User123',
        });
      userToken = userLogin.body.data.accessToken;
    });

    it('ADMIN deve conseguir atualizar roles de usuário', async () => {
      if (!regularUser || !adminRole || !userRole) {
        throw new Error('Dados de teste não inicializados');
      }

      const response = await request(app)
        .put(`/api/users/${regularUser.id}/roles`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          roleIds: [adminRole.id, userRole.id],
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('USER não deve conseguir atualizar roles (403)', async () => {
      if (!regularUser || !adminRole) {
        throw new Error('Dados de teste não inicializados');
      }

      const response = await request(app)
        .put(`/api/users/${regularUser.id}/roles`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          roleIds: [adminRole.id],
        })
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Acesso negado');
    });

    it('deve retornar 401 sem autenticação', async () => {
      if (!regularUser || !adminRole) {
        throw new Error('Dados de teste não inicializados');
      }

      const response = await request(app)
        .put(`/api/users/${regularUser.id}/roles`)
        .send({
          roleIds: [adminRole.id],
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });
});
