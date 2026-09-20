# Privacidade e LGPD — Cactus Fight

> Controles técnicos. Não representam certificação jurídica automática.

## Implementado

- centro de privacidade por usuário;
- exportação dos dados da conta;
- exportação do aluno vinculado, matrículas e eventos de acesso;
- solicitações de acesso, correção, anonimização, exclusão, portabilidade, compartilhamento e oposição;
- consentimentos versionados;
- fila administrativa para OWNER/ADMIN;
- canal de privacidade configurável por academia;
- auditoria;
- respostas da API marcadas como `no-store`.

## Rotas

Titular:

```
GET  /api/privacy
GET  /api/privacy/export
POST /api/privacy/requests
POST /api/privacy/consents
```

Administração:

```
GET   /api/privacy/admin/requests
PATCH /api/privacy/admin/requests/:id
GET   /api/privacy/settings
PUT   /api/privacy/settings
```

## Retenção

Solicitações de exclusão e anonimização não apagam automaticamente histórico de matrícula, financeiro ou controle de acesso. O controlador deve avaliar base legal, finalidade e obrigação de retenção antes da execução.

Antes do primeiro cliente devem existir política publicada, matriz de retenção, definição controlador/operador, subprocessadores e plano de incidentes.
