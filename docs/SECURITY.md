# Segurança — Cactus Fight

## Base implementada

A API central possui agora uma fundação real de segurança para o SaaS:

- Spring Security stateless;
- JWT com issuer e expiração;
- usuário revalidado no PostgreSQL em toda sessão;
- revogação por `auth_version`;
- RBAC server-side;
- isolamento por `academy_id`;
- vínculo opcional Host → academia por domínio verificado;
- MFA TOTP para perfis administrativos;
- Superadmin nominal separado, também com MFA;
- segredo TOTP criptografado com AES-GCM;
- recovery codes armazenados somente como hash;
- recuperação de senha com token de uso único e expiração;
- BCrypt custo 12;
- CORS allowlist;
- security headers;
- request ID e rate limit;
- auditoria de ações sensíveis;
- chaves do Access Agent armazenadas apenas como SHA-256;
- sincronização do Access Agent idempotente;
- PostgreSQL privado no Docker Compose;
- validação de secrets/configuração em produção.

## Multi-tenant

Todas as entidades centrais possuem `academy_id`. O principal autenticado recebe o tenant a partir da sessão revalidada no banco. Rotas de estudante, matrícula, privacidade, domínio e Access Agent filtram pelo tenant server-side.

Quando a requisição chega por um domínio verificado, o filtro JWT também compara o domínio com o `academy_id` da sessão.

## Access Agent

A chave do agente é mostrada somente na criação/rotação. O banco persiste apenas o hash.

Eventos enviados para `POST /api/access/sync` exigem:

- `academyId`;
- `agentId`;
- header `X-Agent-Key`;
- `idempotencyKey`;
- decisão e motivo.

A constraint `UNIQUE(academy_id,idempotency_key)` transforma retries em operação idempotente.

## Concorrência e integridade

- IDs compostos/foreign keys impedem referências cruzadas relevantes;
- uma matrícula aberta por modalidade/aluno é protegida por índice parcial;
- eventos de acesso têm chave de idempotência por tenant;
- onboarding da academia e alterações sensíveis usam transação.

## Produção

Ainda são gates operacionais obrigatórios:

- secret manager;
- TLS/reverse proxy;
- Redis/gateway para rate limit distribuído se houver múltiplas réplicas;
- backup externo + restore testado;
- logs centralizados/alertas;
- pentest/revisão OWASP;
- homologação real de catraca/Wellhub/TotalPass/Asaas.
