package br.com.cactus.fight.security;

import java.util.UUID;

public record PlatformUser(UUID id,String name,String email,int authVersion) {}
