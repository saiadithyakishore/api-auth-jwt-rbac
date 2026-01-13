// ============================================
// TIPOS: Definições TypeScript para a API
// ============================================

// Tipos de autenticação
export interface JWTPayload {
  userId: number;
  username: string;
  email: string;
  roles: string[];
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  fullName: string;
}

export interface AuthResponse {
  token: string; // Mantido para compatibilidade (accessToken)
  accessToken: string; // Access Token (15 minutos)
  refreshToken: string; // Refresh Token (7 dias)
  user: {
    id: number;
    username: string;
    email: string;
    fullName: string;
    roles: string[];
  };
}

// Tipos de usuário
export interface User {
  id: number;
  username: string;
  email: string;
  passwordHash: string;
  fullName: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserWithRoles extends User {
  roles: Role[];
}

export interface CreateUserData {
  username: string;
  email: string;
  password: string;
  fullName: string;
  roleIds?: number[];
}

export interface UpdateUserData {
  email?: string;
  fullName?: string;
  isActive?: boolean;
  roleIds?: number[];
}

// Tipos de role
export interface Role {
  id: number;
  name: string;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface RoleWithPermissions extends Role {
  permissions: Permission[];
}

// Tipos de permissão
export interface Permission {
  id: number;
  name: string;
  description: string | null;
  resource: string;
  action: string;
  createdAt: Date;
  updatedAt: Date;
}

// Tipos de resposta HTTP padronizada
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
}

// Tipos de erro customizado
export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Tipo para usuário com roles e permissões (retorno do repository)
export interface UserWithRolesAndPermissions {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  full_name: string;
  is_active: boolean;
  roles: Role[];
  permissions: Permission[];
}

// Tipos para middleware de autorização
export interface AuthRequest extends Express.Request {
  user?: {
    id: number;
    username: string;
    email: string;
    roles: string[]; // roles do token (garantem consistência com o que foi autenticado)
    dbRoles?: string[]; // roles atuais no banco (opcional, para consulta)
    permissions: string[];
  };
}
