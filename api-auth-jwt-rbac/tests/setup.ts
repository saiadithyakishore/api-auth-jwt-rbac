// ============================================
// SETUP: Configuração global dos testes
// ============================================

import dotenv from 'dotenv';
import { resetTestDatabase } from '../src/config/database';

dotenv.config({ path: '.env.test' });

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_secret_key_min_32_chars_long';
process.env.JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_key_min_32_chars_long';
process.env.JWT_ACCESS_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || '15m';
process.env.JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
process.env.DB_HOST = process.env.DB_HOST || 'localhost';
process.env.DB_USER = process.env.DB_USER || 'root';
process.env.DB_PASSWORD = process.env.DB_PASSWORD || '';
process.env.DB_NAME = process.env.DB_NAME || 'api_auth_rbac_test';
process.env.DB_PORT = process.env.DB_PORT || '3306';

resetTestDatabase();

beforeAll(() => {
  resetTestDatabase();
});

const mute = () => undefined;

if (process.env.NODE_ENV === 'test') {
  jest.spyOn(console, 'log').mockImplementation(mute);
  jest.spyOn(console, 'info').mockImplementation(mute);
  jest.spyOn(console, 'warn').mockImplementation(mute);
  jest.spyOn(console, 'error').mockImplementation(mute);
  jest.spyOn(console, 'debug').mockImplementation(mute);
}

jest.setTimeout(10000);
