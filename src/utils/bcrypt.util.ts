// ============================================
// UTILITÁRIO: Bcrypt para hash de senhas
// ============================================

import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config();

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);

/**
 * Gera hash da senha usando bcrypt
 * @param password - Senha em texto plano
 * @returns Hash da senha
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Compara senha em texto plano com hash
 * @param password - Senha em texto plano
 * @param hash - Hash da senha armazenado
 * @returns true se as senhas coincidem, false caso contrário
 */
export async function comparePassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
