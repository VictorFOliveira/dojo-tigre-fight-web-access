# 🐯 Cactus Fight — Web / Access

Plataforma SaaS multi-tenant para administração de dojôs e academias, com API central, controle de acesso físico e fundação offline-first para o Access Agent.

## Arquitetura inicial

Monorepo com três aplicações:

- `apps/web` — painel administrativo (React + TypeScript)
- `apps/api` — API central (Java 21 + Spring Boot)
- `apps/access` — TIGRE FIGHT ACCESS, agente local da academia (Java 21 + SQLite)

Banco central: PostgreSQL.

## Integrações

- Asaas: cobranças, mensalidades e webhooks. Segredos somente no backend.
- TotalPass: integração através de adapter próprio; implementação deverá seguir exclusivamente a documentação oficial do parceiro.
- Wellhub: integração através de adapter próprio; implementação real depende das credenciais/documentação de parceiro disponibilizadas pela Wellhub.
- Catraca/controladora: Hardware Adapter. Nenhum protocolo será presumido; a implementação será feita após identificação da marca/modelo e consulta à documentação real.

## Regra central de acesso

Credencial -> identificação -> matrícula -> situação financeira/provedor -> bloqueios -> modalidade -> dia/horário -> decisão -> catraca -> evento de auditoria.

Toda decisão deve registrar motivo de liberação/bloqueio.

## Offline-first

O TIGRE FIGHT ACCESS mantém cache SQLite local das permissões necessárias. Sem internet, continua decidindo acessos e grava eventos numa fila local. Ao reconectar, sincroniza de forma idempotente com a API central.

## Princípios

- MVP para uma academia real, preparado para multiacademia.
- Monólito modular antes de microserviços.
- `academy_id` nas entidades centrais.
- UUID/idempotency key em eventos de acesso e sincronização.
- Nenhuma API key no frontend.
- Auditoria de decisões de acesso.
- Hardware e parceiros externos isolados por adapters.

## Fundação implementada

A API central já possui uma base executável em Java 21 / Spring Boot com:

- PostgreSQL + Flyway;
- isolamento por `academy_id`;
- autenticação JWT, RBAC e revogação por `auth_version`;
- MFA TOTP para administrativos e Superadmin;
- recuperação de senha;
- Superadmin nominal separado;
- alunos, matrículas e credenciais de acesso com escopo por tenant;
- Access Agent com chave armazenada como hash e sincronização idempotente;
- auditoria;
- privacidade/LGPD técnica;
- subdomínio Cactus e domínio próprio verificado;
- CORS allowlist, security headers, request ID e rate limit;
- health/metrics/Prometheus;
- Docker Compose com PostgreSQL privado;
- CI da API.

Documentação:

- [Segurança](docs/SECURITY.md)
- [Privacidade/LGPD](docs/PRIVACY.md)
- [Domínios por academia](docs/DOMAINS.md)
- [Checklist de produção](docs/PRODUCTION_CHECKLIST.md)

## Status

**Fundação SaaS/API implementada; produto ainda não está pronto para go-live.** Permanecem o front-end administrativo final, o executável do Access Agent com cache/offline real, homologação de hardware e as integrações externas reais.
