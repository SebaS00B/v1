package com.softevo.camundajhipster.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.rest.security.auth.impl.ContainerBasedAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 * AuthenticationProvider para Camunda que extrae datos desde Keycloak (JWT),
 * mapea/normaliza roles a grupos válidos en Camunda y crea usuario + membership
 * si es la primera autenticación.
 *
 * Registra esta clase como @Component para que Spring la descubra.
 */
@Component
@SuppressWarnings("unchecked")
public class KeycloakCamundaAuthenticationProvider extends ContainerBasedAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakCamundaAuthenticationProvider.class);

    private final CamundaRoleMappingConfiguration mappingConfig;

    public KeycloakCamundaAuthenticationProvider(CamundaRoleMappingConfiguration mappingConfig) {
        this.mappingConfig = mappingConfig;
    }

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            logger.debug("Procesando autenticación para Camunda: {}", authentication);

            if (!(authentication instanceof JwtAuthenticationToken jwtAuth)) {
                logger.debug("No es JwtAuthenticationToken - no autenticado para Camunda");
                return AuthenticationResult.unsuccessful();
            }

            Jwt jwt = jwtAuth.getToken();

            // Extraer roles y grupos
            Set<String> roles = extractUserRoles(jwt);
            logger.debug("Roles extraídos del token: {}", roles);

            if (!hasValidCamundaRole(roles)) {
                logger.warn("Usuario sin roles válidos para Camunda: {}", roles);
                return AuthenticationResult.unsuccessful();
            }

            // Obtener userId y grupos mapeados para Camunda
            String userId = extractUserId(jwt);
            if (userId == null) {
                logger.warn("No se pudo extraer userId del JWT");
                return AuthenticationResult.unsuccessful();
            }

            Set<String> groups = extractGroupIds(jwt, authentication);
            // mapear roles -> grupos usando la configuración
            for (String r : roles) {
                String mapped = mappingConfig.mapRole(r);
                if (mapped != null) groups.add(mapped);
            }

            // eliminar posibles nulos
            groups = groups.stream().filter(Objects::nonNull).collect(Collectors.toSet());
            logger.debug("Grupos finales (normalizados) para Camunda: {}", groups);

            // sincronizar con Camunda (usuarios/grupos/memberships)
            ensureUserExistsInCamunda(engine, jwt, userId, groups);

            AuthenticationResult result = new AuthenticationResult(userId, false);
            result.setAuthenticated(true);
            // optionally set groups in result if supported by your version:
            try {
                result.setGroups(new ArrayList<>(groups));
            } catch (Throwable t) {
                // some Camunda versions may not have setGroups() - ignore safely
            }
            logger.info("Usuario autenticado para Camunda - ID: {}, Grupos: {}", userId, groups);
            return result;
        } catch (Exception e) {
            logger.error("Error extrayendo usuario para Camunda", e);
            return AuthenticationResult.unsuccessful();
        }
    }

    private void ensureUserExistsInCamunda(ProcessEngine engine, Jwt jwt, String userId, Set<String> groupIds) {
        try {
            var identityService = engine.getIdentityService();

            var existingUser = identityService.createUserQuery().userId(userId).singleResult();

            if (existingUser == null) {
                User newUser = identityService.newUser(userId);
                newUser.setFirstName(jwt.getClaimAsString("given_name"));
                newUser.setLastName(jwt.getClaimAsString("family_name"));
                newUser.setEmail(jwt.getClaimAsString("email"));
                identityService.saveUser(newUser);
                logger.info("Usuario creado en Camunda: {}", userId);
            }

            for (String rawGroupId : groupIds) {
                if (rawGroupId == null || rawGroupId.trim().isEmpty()) continue;
                String gid = mappingConfig.mapRole(rawGroupId); // idempotente: mapear o normalizar
                if (gid == null) continue;

                Group g = identityService.createGroupQuery().groupId(gid).singleResult();
                if (g == null) {
                    Group newG = identityService.newGroup(gid);
                    newG.setName(gid);
                    identityService.saveGroup(newG);
                    logger.info("Grupo creado en Camunda: {}", gid);
                }

                // comprobar si el user ya es miembro
                var userMember = identityService.createUserQuery().userId(userId).memberOfGroup(gid).singleResult();

                if (userMember == null) {
                    identityService.createMembership(userId, gid);
                    logger.debug("Usuario {} agregado al grupo {}", userId, gid);
                }
            }
        } catch (Exception ex) {
            logger.warn("Error al sincronizar usuario {} en Camunda: {}", userId, ex.getMessage(), ex);
        }
    }

    private Set<String> extractUserRoles(Jwt jwt) {
        Set<String> roles = new HashSet<>();

        // Claim "roles" directo
        try {
            List<String> direct = jwt.getClaimAsStringList("roles");
            if (direct != null) roles.addAll(direct);
        } catch (Exception ignored) {}

        // realm_access.roles
        try {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Object rObj = realmAccess.get("roles");
                if (rObj instanceof List) roles.addAll((List<String>) rObj);
            }
        } catch (Exception ignored) {}

        // resource_access
        try {
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess != null) {
                for (Object val : resourceAccess.values()) {
                    if (val instanceof Map) {
                        Object clientRoles = ((Map<?, ?>) val).get("roles");
                        if (clientRoles instanceof List) roles.addAll((List<String>) clientRoles);
                    }
                }
            }
        } catch (Exception ignored) {}

        return roles;
    }

    private boolean hasValidCamundaRole(Set<String> roles) {
        return roles
            .stream()
            .anyMatch(
                role ->
                    "ROLE_ADMIN".equals(role) ||
                    "ROLE_USER".equals(role) ||
                    "camunda-admin".equals(role) ||
                    "camunda-user".equals(role) ||
                    "admin".equalsIgnoreCase(role) ||
                    "user".equalsIgnoreCase(role)
            );
    }

    private String extractUserId(Jwt jwt) {
        String preferred = jwt.getClaimAsString("preferred_username");
        if (preferred != null && !preferred.isBlank()) return preferred;
        String email = jwt.getClaimAsString("email");
        if (email != null && !email.isBlank()) return email;
        return jwt.getClaimAsString("sub");
    }

    private Set<String> extractGroupIds(Jwt jwt, Authentication authentication) {
        Set<String> groups = new HashSet<>();

        // claim "groups"
        try {
            List<String> groupsClaim = jwt.getClaimAsStringList("groups");
            if (groupsClaim != null) {
                groups.addAll(groupsClaim.stream().map(g -> g.startsWith("/") ? g.substring(1) : g).collect(Collectors.toSet()));
            }
        } catch (Exception ignored) {}

        // authorities -> mapear y normalizar
        if (authentication != null && authentication.getAuthorities() != null) {
            Set<String> fromAuth = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .map(auth -> {
                    // deja el valor íntegro para que el mapping lo transforme
                    return auth;
                })
                .collect(Collectors.toSet());
            groups.addAll(fromAuth);
        }

        // normalizar/mapper: mapRole() transformará ROLE_ADMIN -> admins, etc.
        return groups.stream().map(mappingConfig::mapRole).filter(Objects::nonNull).collect(Collectors.toSet());
    }
}
