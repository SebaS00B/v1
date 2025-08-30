package com.softevo.camundajhipster.config;

import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.identity.Group;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class CamundaUserInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(CamundaUserInitializer.class);

    private final IdentityService identityService;

    public CamundaUserInitializer(IdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info("Inicializando grupos de Camunda (usuarios vendrán de Keycloak)...");
        createGroupIfNotExists("admins", "Administrators", "SYSTEM");
        createGroupIfNotExists("users", "Regular Users", "WORKFLOW");
        createGroupIfNotExists("camunda-admin", "Camunda Admins", "SYSTEM");
        createGroupIfNotExists("managers", "Managers", "WORKFLOW");
        logger.info("Inicialización de grupos completada.");
    }

    private void createGroupIfNotExists(String groupId, String name, String type) {
        Group existingGroup = identityService.createGroupQuery().groupId(groupId).singleResult();
        if (existingGroup == null) {
            Group group = identityService.newGroup(groupId);
            group.setName(name);
            group.setType(type);
            identityService.saveGroup(group);
            logger.info("Grupo creado: {} ({})", groupId, name);
        } else {
            logger.debug("El grupo {} ya existe", groupId);
        }
    }
}
