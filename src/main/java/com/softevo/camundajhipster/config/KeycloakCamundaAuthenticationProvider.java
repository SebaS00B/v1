package com.softevo.camundajhipster.config;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.rest.security.auth.impl.ContainerBasedAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import jakarta.servlet.http.HttpServletRequest;

@SuppressWarnings("unchecked")
public class KeycloakCamundaAuthenticationProvider extends ContainerBasedAuthenticationProvider {

   @Override
public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication instanceof JwtAuthenticationToken jwtAuth) {
        Jwt jwt = jwtAuth.getToken();

        // Extraer roles de "roles"
        List<String> roles = jwt.getClaimAsStringList("roles");

        // Si no hay "roles", usar "realm_access.roles"
        if (roles == null || roles.isEmpty()) {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                roles = (List<String>) realmAccess.get("roles");
            }
        }

        if (roles != null) {
            if (roles.contains("ROLE_ADMIN") || roles.contains("ROLE_USER")) {
                // ✅ Aquí ya basta con devolver el userId
                return new AuthenticationResult(extractUserId(request), true);
            }
        }
    }

    return AuthenticationResult.unsuccessful();
}


    public String extractUserId(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                Jwt jwt = jwtAuth.getToken();

                // Prioridad: preferred_username > email > sub
                String preferredUsername = jwt.getClaimAsString("preferred_username");
                if (preferredUsername != null) return preferredUsername;

                String email = jwt.getClaimAsString("email");
                if (email != null) return email;

                return jwt.getClaimAsString("sub");
            }
            return authentication.getName();
        }
        return null;
    }

    public Set<String> extractGroupIds(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                Jwt jwt = jwtAuth.getToken();

                // 1. Intentar claim "groups"
                List<String> groups = jwt.getClaimAsStringList("groups");
                if (groups != null) {
                    return groups.stream()
                        .map(g -> g.startsWith("/") ? g.substring(1) : g)
                        .collect(Collectors.toSet());
                }

                // 2. Intentar usar authorities de Spring
                return authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(auth -> auth.startsWith("ROLE_") ? auth.substring(5) : auth)
                    .collect(Collectors.toSet());
            }
        }

        return Collections.emptySet();
    }
}