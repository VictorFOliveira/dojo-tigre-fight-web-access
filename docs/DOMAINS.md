# Domínios por academia — Cactus Fight

Cada academia pode usar um endereço Cactus:

```
<slug>.fight.cactustecnologia.com.br
```

e, opcionalmente, domínio próprio:

```
alunos.academia.com.br
```

Para domínio próprio:

```
alunos.academia.com.br CNAME custom.fight.cactustecnologia.com.br
```

A API consulta o CNAME e só marca o domínio como verificado quando o destino corresponde ao configurado.

## Rotas

```
GET    /api/domains
POST   /api/domains
POST   /api/domains/:id/verify
POST   /api/domains/:id/primary
DELETE /api/domains/:id
```

Somente OWNER/ADMIN gerenciam domínios.

Quando o host corresponde a um domínio verificado, a sessão precisa pertencer à mesma academia.
