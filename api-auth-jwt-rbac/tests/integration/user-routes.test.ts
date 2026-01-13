// ============================================
// TESTES DE INTEGRAÇÃO: Rotas de Usuários
// ============================================

import request from 'supertest';
import app from '../../src/app';
import { hashPassword } from '../../src/utils/bcrypt.util';
import { query, resetTestDatabase } from '../../src/config/database';
import * as userRepository from '../../src/repositories/user.repository';
import * as roleRepository from '../../src/repositories/role.repository';
import { Role, User } from '../../src/types';

describe('User Routes Integration', () => {
  let adminToken!: string;
  let userToken!: string;
  let adminRole!: Role;
  let userRole!: Role;
  let managerRole!: Role;
  let adminUser!: User;
  let regularUser!: User;
  let roleTargetUser!: User;

  beforeAll(async () => {
    resetTestDatabase();

    adminRole = (await roleRepository.findByName('ADMIN')) as Role;
    userRole = (await roleRepository.findByName('USER')) as Role;
    managerRole = (await roleRepository.findByName('MANAGER')) as Role;

    if (!adminRole) {
      const adminRoleResult = await query(
        'INSERT INTO roles (name, description) VALUES (?, ?)',
        ['ADMIN', 'Administrador']
      );
      adminRole = (await roleRepository.findById(adminRoleResult.insertId)) as Role;
    }

    if (!userRole) {
      const userRoleResult = await query(
        'INSERT INTO roles (name, description) VALUES (?, ?)',
        ['USER', 'Usuário padrão']
      );
      userRole = (await roleRepository.findById(userRoleResult.insertId)) as Role;
    }

    if (!managerRole) {
      const managerRoleResult = await query(
        'INSERT INTO roles (name, description) VALUES (?, ?)',
        ['MANAGER', 'Gerente']
      );
      managerRole = (await roleRepository.findById(managerRoleResult.insertId)) as Role;
    }

    const adminPasswordHash = await hashPassword('Admin123!');
    const adminInsert = await query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active) 
       VALUES (?, ?, ?, ?, ?)`,
      ['admin_integration', 'admin.integration@test.com', adminPasswordHash, 'Admin Integration', true]
    );
    const adminCreated = await userRepository.findById(adminInsert.insertId);
    if (!adminCreated) {
      throw new Error('Não foi possível criar o usuário admin de teste');
    }
    adminUser = adminCreated;
    await query('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [adminUser.id, adminRole.id]);

    const userPasswordHash = await hashPassword('User123!');
    const userInsert = await query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active) 
       VALUES (?, ?, ?, ?, ?)`,
      ['user_integration', 'user.integration@test.com', userPasswordHash, 'User Integration', true]
    );
    const regularCreated = await userRepository.findById(userInsert.insertId);
    if (!regularCreated) {
      throw new Error('Não foi possível criar o usuário padrão de teste');
    }
    regularUser = regularCreated;
    await query('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [regularUser.id, userRole.id]);

    const roleTargetPassword = await hashPassword('Target123!');
    const roleTargetInsert = await query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active) 
       VALUES (?, ?, ?, ?, ?)`,
      ['role_target', 'role.target@test.com', roleTargetPassword, 'Role Target', true]
    );
    const roleTargetCreated = await userRepository.findById(roleTargetInsert.insertId);
    if (!roleTargetCreated) {
      throw new Error('Não foi possível criar o usuário alvo para roles');
    }
    roleTargetUser = roleTargetCreated;
    await query('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [roleTargetUser.id, userRole.id]);

    const adminLogin = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'admin_integration',
        password: 'Admin123!',
      });
    adminToken = adminLogin.body.data.accessToken;

    const userLogin = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'user_integration',
        password: 'User123!',
      });
    userToken = userLogin.body.data.accessToken;
  });

  describe('POST /api/users', () => {
    it('deve criar usuário com role USER automaticamente', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'senha123',
          fullName: 'Test User',
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data.roles).toEqual(['USER']);
    });

    it('deve ignorar roleIds enviado pelo frontend', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          username: 'testuser2',
          email: 'test2@example.com',
          password: 'senha123',
          fullName: 'Test User 2',
          roleIds: [adminRole.id],
        });

      expect(response.body.data.roles).toEqual(['USER']);
    });

    it('deve retornar 403 se usuário não for ADMIN', async () => {
      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          username: 'testuser3',
          email: 'test3@example.com',
          password: 'senha123',
          fullName: 'Test User 3',
        });

      expect(response.status).toBe(403);
    });
  });

  describe('PUT /api/users/:id/roles', () => {
    it('deve atualizar roles apenas se for ADMIN', async () => {
      const response = await request(app)
        .put(`/api/users/${roleTargetUser.id}/roles`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          roleIds: [adminRole.id, managerRole.id],
        });

      expect(response.status).toBe(200);
      expect(response.body.data.roles).toContain('ADMIN');
      expect(response.body.data.roles).toContain('MANAGER');
    });

    it('deve retornar 403 se não for ADMIN', async () => {
      const response = await request(app)
        .put(`/api/users/${roleTargetUser.id}/roles`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          roleIds: [adminRole.id],
        });

      expect(response.status).toBe(403);
    });

    it('deve validar que roles existem', async () => {
      const response = await request(app)
        .put(`/api/users/${roleTargetUser.id}/roles`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          roleIds: [9999],
        });

      expect(response.status).toBe(400);
    });
  });
});
