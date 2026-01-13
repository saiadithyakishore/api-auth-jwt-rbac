# 🔐 API REST - Autenticação e Autorização RBAC

> API REST focada em autenticação segura, RBAC e boas práticas de backend.  
> Projeto desenvolvido para demonstrar arquitetura, testes e padrões usados em ambientes corporativos.

## 🎯 Objetivo do Projeto

Este projeto foi criado para demonstrar:
- Implementação correta de JWT + Refresh Token
- Controle de acesso por roles (RBAC)
- Arquitetura backend escalável
- Testes automatizados reais
- Padrões usados em APIs corporativas

## 📋 Índice

- [Características](#-características)
- [Stack Tecnológica](#-stack-tecnológica)
- [Arquitetura](#-arquitetura)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Banco de Dados](#-banco-de-dados)
- [Endpoints](#-endpoints)
- [Autenticação](#-autenticação)
- [Autorização](#-autorização)
- [Exemplos de Uso](#-exemplos-de-uso)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Decisões Técnicas](#-decisões-técnicas)

## ✨ Características Enterprise

- ✅ **JWT com Refresh Token** (Access 15min + Refresh 7d, rotação e revogação do anterior)
- ✅ **Logout com Blacklist** (tokens revogados invalidados imediatamente)
- ✅ **RBAC por role** (ADMIN/USER/MANAGER) e endpoint de gerenciamento de roles
- ✅ **Middleware requireRoles** para controle de acesso
- ✅ **Swagger/OpenAPI** em `/api-docs`
- ✅ **Logging estruturado** (Winston)
- ✅ **Auditoria** (tabela de audit logs)
- ✅ **Validações com Zod** e respostas HTTP padronizadas
- ✅ **Arquitetura em camadas** (Routes → Controllers → Services → Repositories)
- ✅ **Testes automatizados (Jest + Supertest)** cobrindo login, RBAC, refresh token e logout

<details>
<summary>📘 Detalhes Técnicos Avançados</summary>

- Tokens usam `jwtid` para garantir unicidade e rotação real de refresh tokens  
- Blacklist em memória (sugestão: Redis em produção)  
- Auditoria armazenada em `audit_logs`  
- Swagger configurado via `swagger-jsdoc` e servido em `/api-docs`  
- Logs estruturados com Winston (console em dev + arquivos)  
- Validação de entrada com Zod e helpers padronizados de resposta  
- Middleware de autenticação carrega roles e permissões reais do banco  
- Estrutura de serviços e repositórios separa regras de negócio de acesso a dados  

</details>

## 🛠 Stack Tecnológica

- **Runtime:** Node.js
- **Framework:** Express.js
- **Linguagem:** TypeScript
- **Banco de Dados:** MySQL
- **Autenticação:** JWT (JSON Web Token)
- **Hash de Senhas:** Bcrypt
- **Gerenciamento de Variáveis:** dotenv

## 🏗 Arquitetura

A API segue uma arquitetura em camadas bem definida:

```
┌─────────────────────────────────────┐
│         Routes (Rotas)              │  ← Definição de endpoints
├─────────────────────────────────────┤
│      Controllers (Controladores)    │  ← Lógica de requisições HTTP
├─────────────────────────────────────┤
│        Services (Serviços)          │  ← Lógica de negócio
├─────────────────────────────────────┤
│     Repositories (Repositórios)    │  ← Acesso a dados
├─────────────────────────────────────┤
│         Database (MySQL)            │  ← Persistência
└─────────────────────────────────────┘
```

### Camadas

1. **Routes:** Define os endpoints e aplica middlewares de autenticação/autorização
2. **Controllers:** Processa requisições HTTP, valida dados e chama services
3. **Services:** Contém a lógica de negócio e validações
4. **Repositories:** Abstrai o acesso ao banco de dados
5. **Middlewares:** Autenticação, autorização e tratamento de erros
6. **Utils:** Funções utilitárias (JWT, Bcrypt)

## 📦 Instalação

### Pré-requisitos

- Node.js (v18 ou superior)
- MySQL Server (v8.0 ou superior)
- npm ou yarn

### Passos

1. **Clone o repositório:**
```bash
git clone <url-do-repositorio>
cd projeto-apirest
```

2. **Instale as dependências:**
```bash
npm install
```

3. **Configure as variáveis de ambiente:**
```bash
# Copie o arquivo .env.example para .env
cp .env.example .env

# Edite o arquivo .env com suas configurações
```

4. **Configure o banco de dados:**
```bash
# Execute o schema SQL no MySQL Workbench ou via linha de comando
mysql -u root -p < database/schema.sql

# Execute o seed para popular dados iniciais
mysql -u root -p < database/seed.sql
```

5. **Compile o TypeScript:**
```bash
npm run build
```

6. **Inicie o servidor:**
```bash
# Modo desenvolvimento (com hot-reload)
npm run dev

# Modo produção
npm start
```

## ⚙️ Configuração

### Variáveis de Ambiente (.env)

```env
# Servidor
PORT=3000
NODE_ENV=development

# Banco de Dados MySQL
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=sua_senha_aqui
DB_NAME=api_auth_rbac

# JWT
JWT_SECRET=seu_jwt_secret_super_seguro_aqui_mude_em_producao
JWT_EXPIRES_IN=24h

# Segurança
BCRYPT_ROUNDS=10
```

**⚠️ IMPORTANTE:** Em produção, altere o `JWT_SECRET` para um valor seguro e aleatório!

## 🗄 Banco de Dados

### Schema

O banco de dados possui as seguintes tabelas:

- **users:** Usuários do sistema
- **roles:** Papéis (ADMIN, MANAGER, USER)
- **permissions:** Permissões granulares (USER_CREATE, USER_READ, etc.)
- **user_roles:** Relacionamento N:N entre usuários e roles
- **role_permissions:** Relacionamento N:N entre roles e permissões
- **audit_logs:** Logs de auditoria para ações sensíveis

### Roles Padrão

- **ADMIN:** Acesso total a todas as funcionalidades
- **MANAGER:** Permissões de gerenciamento (sem delete)
- **USER:** Permissões básicas de leitura

### Permissões Padrão

- `USER_CREATE`, `USER_READ`, `USER_UPDATE`, `USER_DELETE`
- `ROLE_CREATE`, `ROLE_READ`, `ROLE_UPDATE`, `ROLE_DELETE`
- `PERMISSION_CREATE`, `PERMISSION_READ`, `PERMISSION_UPDATE`, `PERMISSION_DELETE`
- `AUDIT_READ`

## 🔌 Endpoints

### Autenticação

#### POST `/api/auth/register`
Registra um novo usuário.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "senha123",
  "fullName": "John Doe"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Usuário registrado com sucesso",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "johndoe",
      "email": "john@example.com",
      "fullName": "John Doe",
      "roles": []
    }
  }
}
```

#### POST `/api/auth/login`
Autentica um usuário e retorna token JWT.

**Request Body:**
```json
{
  "username": "johndoe",
  "password": "senha123"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login realizado com sucesso",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "johndoe",
      "email": "john@example.com",
      "fullName": "John Doe",
      "roles": ["USER"]
    }
  }
}
```

#### GET `/api/auth/me`
Retorna informações do usuário autenticado.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "success": true,
  "message": "Dados do usuário recuperados com sucesso",
  "data": {
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com",
    "fullName": "John Doe",
    "roles": ["USER"],
    "isActive": true,
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

#### POST `/api/auth/refresh-token`
Renova Access Token usando Refresh Token (com rotação).

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Token renovado com sucesso",
  "data": {
    "accessToken": "novo_access_token",
    "refreshToken": "novo_refresh_token"
  }
}
```

**Nota:** O refresh token antigo é automaticamente revogado após a rotação.

#### POST `/api/auth/logout`
Realiza logout do usuário (revoga tokens).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body (opcional):**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "revokeAll": false
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Logout realizado com sucesso",
  "data": {
    "message": "Logout realizado com sucesso"
  }
}
```

**Parâmetros:**
- `refreshToken` (opcional): Revoga o refresh token fornecido
- `revokeAll` (opcional, padrão: `false`): Se `true`, revoga todos os tokens do usuário

### Usuários

#### GET `/api/users`
Lista todos os usuários (requer permissão `USER_READ`).

**Headers:**
```
Authorization: Bearer <token>
```

**Query Parameters:**
- `limit` (opcional): Número de resultados (padrão: 50)
- `offset` (opcional): Offset para paginação (padrão: 0)

#### GET `/api/users/:id`
Busca um usuário por ID (requer permissão `USER_READ`).

#### POST `/api/users`
Cria um novo usuário (requer permissão `USER_CREATE`).

**Request Body:**
```json
{
  "username": "janedoe",
  "email": "jane@example.com",
  "password": "senha123",
  "fullName": "Jane Doe",
  "roleIds": [1, 2]
}
```

#### PUT `/api/users/:id`
Atualiza um usuário (requer permissão `USER_UPDATE`).

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "fullName": "Jane Smith",
  "isActive": true,
  "roleIds": [2]
}
```

#### DELETE `/api/users/:id`
Deleta um usuário (requer permissão `USER_DELETE`).

**Query Parameters:**
- `hard` (opcional): Se `true`, faz hard delete (padrão: `false` - soft delete)

## 🔐 Autenticação

A autenticação é feita via **JWT (JSON Web Token)** com estratégia de **Access Token + Refresh Token**.

### Estratégia de Tokens

- **Access Token:** Válido por **15 minutos** (curto, para segurança)
- **Refresh Token:** Válido por **7 dias** (longo, para conveniência)

### Fluxo de Autenticação

1. **Login:** Cliente recebe `accessToken` e `refreshToken`
2. **Uso:** Cliente usa `accessToken` em todas as requisições
3. **Renovação:** Quando `accessToken` expira, cliente usa `refreshToken` para obter novo par
4. **Rotação:** Refresh token antigo é automaticamente revogado após renovação
5. **Logout:** Tokens são adicionados à blacklist e invalidados

### Enviar Token

Após o login, o access token deve ser enviado no header `Authorization`:

```
Authorization: Bearer <access_token>
```

### Estrutura do Token

O Access Token JWT contém:
- `userId`: ID do usuário
- `username`: Nome de usuário
- `email`: Email do usuário
- `roles`: Array de roles do usuário
- `iat`: Data de emissão
- `exp`: Data de expiração
- `iss`: Emissor (issuer)
- `aud`: Audiência (audience)

### Blacklist de Tokens

Tokens revogados (logout) são adicionados à blacklist em memória. Em produção, recomenda-se migrar para Redis para:
- Persistência entre reinicializações
- Compartilhamento entre múltiplas instâncias
- TTL automático

## 🛡 Autorização

A autorização funciona em dois níveis:

### 1. Por Role (RBAC)

Verifica se o usuário possui uma das roles necessárias:

```typescript
// Exemplo: Apenas ADMIN
router.get('/admin', authenticate, requireRoles('ADMIN'), controller);

// Exemplo: ADMIN ou MANAGER
router.get('/admin-or-manager', authenticate, requireRoles('ADMIN', 'MANAGER'), controller);
```

**Middleware:** `requireRoles(...roles: string[])`
- Retorna 401 se não autenticado
- Retorna 403 se autenticado sem role necessária
- Logs estruturados de acesso negado

### 2. Por Permissão

Verifica se o usuário possui uma permissão específica:

```typescript
// Exemplo: Requer permissão USER_CREATE
router.post('/users', authenticate, authorizePermission('USER_CREATE'), controller);
```

**Middleware:** `authorizePermission(permission: string)`
- Retorna 401 se não autenticado
- Retorna 403 se autenticado sem permissão

### Códigos de Status

- **401 Unauthorized:** Token ausente, inválido ou expirado
- **403 Forbidden:** Usuário autenticado, mas sem permissão suficiente

## 📝 Exemplos de Uso

### 1. Registrar um novo usuário

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "senha123",
    "fullName": "John Doe"
  }'
```

### 2. Fazer login

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "senha123"
  }'
```

### 3. Acessar endpoint protegido

```bash
curl -X GET http://localhost:3000/api/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 4. Criar um novo usuário (requer permissão)

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "janedoe",
    "email": "jane@example.com",
    "password": "senha123",
    "fullName": "Jane Doe",
    "roleIds": [1]
  }'
```

## 📁 Estrutura do Projeto

```
projeto-apirest/
├── src/
│   ├── config/
│   │   └── database.ts          # Configuração do banco de dados
│   ├── controllers/
│   │   ├── auth.controller.ts   # Controllers de autenticação
│   │   └── user.controller.ts   # Controllers de usuários
│   ├── middlewares/
│   │   ├── auth.middleware.ts   # Middlewares de auth/autorização
│   │   └── error.middleware.ts  # Tratamento de erros
│   ├── repositories/
│   │   ├── user.repository.ts   # Acesso a dados de usuários
│   │   ├── role.repository.ts   # Acesso a dados de roles
│   │   ├── permission.repository.ts
│   │   └── audit.repository.ts  # Logs de auditoria
│   ├── routes/
│   │   ├── auth.routes.ts       # Rotas de autenticação
│   │   └── user.routes.ts       # Rotas de usuários
│   ├── services/
│   │   ├── auth.service.ts      # Lógica de negócio de auth
│   │   └── user.service.ts      # Lógica de negócio de usuários
│   ├── types/
│   │   └── index.ts             # Definições TypeScript
│   ├── utils/
│   │   ├── jwt.util.ts          # Utilitários JWT
│   │   └── bcrypt.util.ts       # Utilitários Bcrypt
│   ├── app.ts                    # Configuração do Express
│   └── server.ts                 # Inicialização do servidor
├── database/
│   ├── schema.sql                # Schema do banco de dados
│   └── seed.sql                  # Dados iniciais
├── .env.example                  # Exemplo de variáveis de ambiente
├── .gitignore
├── package.json
├── tsconfig.json
└── README.md
```

## 🎯 Decisões Técnicas

### 1. Arquitetura em Camadas

**Decisão:** Separar responsabilidades em camadas bem definidas.

**Benefícios:**
- Facilita manutenção e testes
- Permite reutilização de código
- Melhora a organização do projeto

### 2. TypeScript

**Decisão:** Usar TypeScript em vez de JavaScript puro.

**Benefícios:**
- Tipagem estática reduz erros
- Melhor autocompletar e IntelliSense
- Código mais seguro e manutenível

### 3. Pool de Conexões MySQL

**Decisão:** Usar pool de conexões em vez de conexões únicas.

**Benefícios:**
- Melhor performance
- Gerenciamento eficiente de recursos
- Suporta múltiplas requisições simultâneas

### 4. JWT para Autenticação

**Decisão:** Usar JWT em vez de sessões.

**Benefícios:**
- Stateless (não requer armazenamento no servidor)
- Escalável
- Padrão da indústria

### 5. Bcrypt para Hash de Senhas

**Decisão:** Usar bcrypt com 10 rounds.

**Benefícios:**
- Algoritmo seguro e amplamente usado
- Resistente a ataques de força bruta
- Configurável via variável de ambiente

### 6. Sistema de Auditoria

**Decisão:** Implementar tabela de audit_logs.

**Benefícios:**
- Rastreabilidade de ações sensíveis
- Compliance e segurança
- Facilita debugging

### 7. Tratamento Centralizado de Erros

**Decisão:** Middleware único para tratamento de erros.

**Benefícios:**
- Respostas padronizadas
- Fácil manutenção
- Logs consistentes

### 8. Soft Delete

**Decisão:** Implementar soft delete por padrão.

**Benefícios:**
- Preserva histórico de dados
- Permite recuperação
- Melhor para auditoria

## 🔧 Troubleshooting

### Problemas Comuns

#### Erro: "Access denied for user 'root'@'localhost'"
**Solução:** Verifique se o arquivo `.env` existe e se `DB_PASSWORD` está configurado corretamente.

#### Erro: "ECONNREFUSED"
**Solução:** Verifique se o MySQL está rodando. No Windows, execute:
```powershell
Get-Service -Name "*MySQL*"
Start-Service -Name "MySQL80"
```

#### Erro: "Unknown database 'api_auth_rbac'"
**Solução:** Execute o arquivo `database/schema.sql` no MySQL Workbench para criar o banco.

#### Erro: Hash da senha incorreto (11 caracteres em vez de 60)
**Solução:** Execute o script para corrigir:
```bash
npm run fix-admin-password
```

#### Erro: "ts-node-dev não é reconhecido"
**Solução:** Instale as dependências:
```bash
npm install
```

### Criar Usuário Admin

**Opção 1: Via Script**
```bash
npm run create-admin
```

**Opção 2: Via MySQL Workbench**
Execute `database/create-admin.sql` e ajuste a senha conforme necessário.

**Opção 3: Via API (após ter um token com permissão USER_CREATE)**
```bash
POST /api/users
Authorization: Bearer <token>
Body: {
  "username": "admin",
  "email": "admin@example.com",
  "password": "Admin@123",
  "fullName": "Administrador",
  "roleIds": [1]
}
```

### Gerar Token de Admin

1. Faça login com o usuário admin:
```bash
POST /api/auth/login
Body: {
  "username": "admin",
  "password": "Admin@123"
}
```

2. Copie o token da resposta e use no header:
```
Authorization: Bearer <token>
```

## 🧪 Testes

A API inclui testes automatizados usando **Jest** e **Supertest**.

### Executar Testes

```bash
# Executar todos os testes
npm test

# Executar em modo watch
npm run test:watch

# Executar com cobertura
npm run test:coverage
```

### Cobertura de Testes

- ✅ **Login:** Credenciais válidas, inválidas, usuário inexistente
- ✅ **Autenticação:** Token válido, inválido, expirado, sem token
- ✅ **RBAC:** ADMIN acessa, USER não acessa, sem autenticação
- ✅ **Refresh Token:** Renovação, rotação, token inválido
- ✅ **Logout:** Logout bem-sucedido, token invalidado após logout

### Estrutura de Testes

```
tests/
├── setup.ts              # Configuração global
├── auth.test.ts          # Testes de autenticação
├── rbac.test.ts          # Testes de RBAC
└── refresh-token.test.ts # Testes de refresh token
```

## 🚀 Funcionalidades Implementadas

- Validação com Zod
- Tokens Access + Refresh com rotação (refresh antigo revogado)
- Logout com blacklist de tokens
- RBAC com middleware `requireRoles` e endpoint de gerenciamento de roles
- Swagger/OpenAPI disponível em `/api-docs`
- Logging estruturado (Winston)
- Testes automatizados (Jest + Supertest) cobrindo login, RBAC, refresh token e logout
- Respostas HTTP padronizadas (helpers)

## 📄 Licença

Este projeto é open source e está disponível para uso educacional e profissional.

## 👨‍💻 Autor

Desenvolvido como projeto de portfólio profissional.

---

**⭐ Se este projeto foi útil, considere dar uma estrela no repositório!**
