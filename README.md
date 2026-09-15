# DOJÔ TIGRE FIGHT WEB / ACCESS

Plataforma web de administração de dojôs/academias com controle de acesso físico e operação offline.

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

## Status

Projeto em bootstrap. A primeira etapa é estabelecer contratos, infraestrutura local e módulos-base antes da integração com uma catraca específica.
