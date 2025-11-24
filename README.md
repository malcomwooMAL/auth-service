# Auth Service

Este projeto é um microserviço de autenticação construído com **Spring Boot** e **Spring Security OAuth2 Authorization Server**. Ele fornece funcionalidades para registro de usuários e emissão de tokens de acesso usando o fluxo OAuth2.

## Tecnologias Utilizadas

*   **Java 21**: Linguagem de programação.
*   **Spring Boot 3.3.6**: Framework para desenvolvimento rápido de aplicações.
*   **Spring Security**: Framework de segurança.
*   **Spring OAuth2 Authorization Server**: Implementação de servidor de autorização OAuth 2.1 e OpenID Connect 1.0.
*   **PostgreSQL**: Banco de dados relacional.
*   **Docker & Docker Compose**: Para containerização e orquestração do banco de dados.
*   **SpringDoc OpenAPI (Swagger)**: Para documentação da API.

## Pré-requisitos

Para executar este projeto, você precisará ter instalado em sua máquina:

*   [Java JDK 21](https://adoptium.net/)
*   [Maven](https://maven.apache.org/) (opcional se usar o wrapper `mvnw`)
*   [Docker](https://www.docker.com/) e Docker Compose

## Configuração e Execução

### 1. Clonar o Repositório

```bash
git clone <url-do-repositorio>
cd auth-service
```

### 2. Iniciar o Banco de Dados

Utilize o Docker Compose para subir uma instância do PostgreSQL configurada para o projeto.

```bash
docker-compose up -d
```

Isso iniciará o banco de dados PostgreSQL na porta **5433** (mapeada da 5432 interna) e criará o banco `auth_db` com as tabelas necessárias (definidas em `init.sql`).

### 3. Executar a Aplicação

Você pode executar a aplicação usando o Maven:

```bash
./mvnw spring-boot:run
```
ou
```bash
mvn spring-boot:run
```

A aplicação estará acessível em `http://localhost:9000`.

## Documentação da API (Swagger UI)

Após iniciar a aplicação, você pode acessar a documentação interativa da API através do Swagger UI:

👉 **[http://localhost:9000/swagger-ui.html](http://localhost:9000/swagger-ui.html)**

Lá você encontrará detalhes sobre todos os endpoints, esquemas de dados e poderá testar as requisições diretamente pelo navegador.

## Utilização da API

Abaixo estão exemplos de como utilizar os principais endpoints via `cURL`.

### Registrar um Novo Usuário

Endpoint para criar um novo usuário no sistema.

**Requisição:**

```bash
curl -X POST http://localhost:9000/api/auth/registrar \
  -H "Content-Type: application/json" \
  -d '{
    "username": "meu_usuario",
    "password": "minha_senha_secreta"
  }'
```

**Resposta de Sucesso (200 OK):**
```
User registered successfully
```

### Realizar Login (Obter Token)

O endpoint `/api/auth/login` foi criado para simplificar o processo de login para clientes que desejam enviar usuário e senha diretamente. Ele atua como um **proxy** para o endpoint padrão de token do OAuth2 (`/oauth2/token`).

**Requisição:**

```bash
curl -X POST http://localhost:9000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "meu_usuario",
    "password": "minha_senha_secreta"
  }'
```

**Resposta de Sucesso (200 OK):**

A resposta será um JSON contendo o `access_token` e outras informações do OAuth2.

```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid"
}
```

## Fluxo de Autenticação Detalhado

O serviço utiliza o **Spring Authorization Server**. Embora tenhamos criado um endpoint `/api/auth/login` para conveniência, o fluxo subjacente é o **OAuth2 Resource Owner Password Credentials Grant** (embora deprecated em novas specs, é usado aqui internamente ou simulado) ou similar, onde a aplicação cliente (o próprio controller) se autentica como um cliente OAuth2 (`client` / `secret`) e troca as credenciais do usuário pelo token.

### Detalhes Internos do `/api/auth/login`:

1.  O cliente envia `username` e `password` para `/api/auth/login`.
2.  O `AuthController` constrói uma requisição para o endpoint `/oauth2/token` (na própria aplicação).
3.  Ele adiciona o cabeçalho `Authorization: Basic ...` com as credenciais do cliente OAuth configurado (`client:secret`).
4.  Ele envia os parâmetros `grant_type=password`, `username` e `password`.
5.  O Authorization Server valida as credenciais e retorna o token JWT/Opaco.
6.  O `AuthController` repassa a resposta para o cliente original.

Isso permite que clientes simples (como um frontend web ou mobile) façam login sem precisar implementar toda a complexidade de chamadas OAuth2 diretamente, se assim desejarem.

## Estrutura do Projeto

*   `src/main/java/.../config`: Configurações de Segurança e OpenAPI.
*   `src/main/java/.../controller`: Endpoints da API.
*   `src/main/java/.../service`: Lógica de negócios.
*   `src/main/java/.../model`: Entidades JPA.
*   `src/main/java/.../dto`: Objetos de transferência de dados.
*   `src/main/java/.../repository`: Interfaces de acesso a dados.

## Contribuição

Sinta-se à vontade para abrir issues ou pull requests para melhorias na documentação ou no código.
