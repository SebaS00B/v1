package com.softevo.camundajhipster.config;

import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración para mapeo de roles de Keycloak a grupos de Camunda
 */
@Configuration
@ConfigurationProperties(prefix = "camunda.role-mapping")
public class CamundaRoleMappingConfiguration {

    private Map<String, String> keycloakToCamunda = new HashMap<>();

    public CamundaRoleMappingConfiguration() {
        // Configuración por defecto
        keycloakToCamunda.put("ROLE_ADMIN", "admins");
        keycloakToCamunda.put("ROLE_USER", "users");
        keycloakToCamunda.put("admin", "admins");
        keycloakToCamunda.put("user", "users");
        keycloakToCamunda.put("Admins", "admins");
        keycloakToCamunda.put("Users", "users");
        keycloakToCamunda.put("camunda-admin", "camunda-admin");
        keycloakToCamunda.put("manager", "managers");
    }

    public Map<String, String> getKeycloakToCamunda() {
        return keycloakToCamunda;
    }

    public void setKeycloakToCamunda(Map<String, String> keycloakToCamunda) {
        this.keycloakToCamunda = keycloakToCamunda;
    }

    public String mapRole(String keycloakRole) {
        return keycloakToCamunda.getOrDefault(keycloakRole, normalizeGroupName(keycloakRole));
    }

    /**
     * Normaliza nombres de grupos para que sean válidos en Camunda
     */
    private String normalizeGroupName(String groupName) {
        if (groupName == null || groupName.trim().isEmpty()) {
            return null;
        }

        String normalized = groupName
            .toLowerCase()
            .replaceAll("[^a-z0-9\\-]", "-") // Reemplazar caracteres no válidos con -
            .replaceAll("-+", "-") // Reemplazar múltiples - con uno solo
            .replaceAll("^-|-$", ""); // Remover - al inicio y final

        // Si empieza con número, agregar prefijo
        if (normalized.matches("^\\d.*")) {
            normalized = "group-" + normalized;
        }

        // Si está vacío después de normalización, devolver null
        return normalized.isEmpty() ? null : normalized;
    }
}
