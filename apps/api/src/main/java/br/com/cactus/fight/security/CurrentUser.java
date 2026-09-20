package br.com.cactus.fight.security;

import java.util.UUID;

public record CurrentUser(UUID id, UUID academyId, String name, String email, String role, int authVersion) {}
