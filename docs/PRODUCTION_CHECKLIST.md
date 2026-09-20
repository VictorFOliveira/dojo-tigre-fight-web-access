# Checklist de produção — Cactus Fight

## Fundação técnica
- [x] API Java 21 / Spring Boot.
- [x] PostgreSQL + Flyway.
- [x] multi-tenant por `academy_id`.
- [x] autenticação, RBAC e sessões revogáveis.
- [x] MFA administrativo e Superadmin.
- [x] recuperação de senha.
- [x] privacidade/LGPD técnica.
- [x] domínio/subdomínio por tenant.
- [x] Access Agent com chave hash e sync idempotente.
- [x] auditoria.
- [x] request ID, rate limit e security headers.
- [x] health/metrics/Prometheus.
- [x] Docker e Compose com PostgreSQL privado.
- [x] CI de compilação/teste/build da imagem.

## Go-live
- [ ] front-end administrativo final.
- [ ] agente Access executável com cache SQLite/offline real.
- [ ] integração física homologada com a catraca escolhida.
- [ ] Asaas homologado.
- [ ] contratos/credenciais oficiais Wellhub e TotalPass.
- [ ] TLS e reverse proxy.
- [ ] secrets em secret manager.
- [ ] backup externo e restore testado.
- [ ] rate limit distribuído se houver mais de uma réplica.
- [ ] logs centralizados e alertas.
- [ ] teste de carga.
- [ ] regressão destrutiva pós-deploy.
- [ ] pentest/revisão OWASP.
- [ ] política LGPD e retenção aprovadas.
