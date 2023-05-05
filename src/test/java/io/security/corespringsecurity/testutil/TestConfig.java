package io.security.corespringsecurity.testutil;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.service.ResourcesService;
import io.security.corespringsecurity.service.RoleService;
import io.security.corespringsecurity.service.UserService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;

/**
 * test 에 필요한 Bean 등록
 */
@TestConfiguration
@ComponentScan(basePackages = {"io.security.corespringsecurity.security"})
public class TestConfig {
    @MockBean
    UserRepository userRepository;
    @MockBean
    UserService userService;

    @MockBean
    ResourcesRepository resourcesRepository;
    @MockBean
    ResourcesService resourcesService;

    @MockBean
    RoleRepository roleRepository;
    @MockBean
    RoleService roleService;
}
