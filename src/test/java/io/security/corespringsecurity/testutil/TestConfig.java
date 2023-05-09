package io.security.corespringsecurity.testutil;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.service.ResourcesService;
import io.security.corespringsecurity.service.RoleService;
import io.security.corespringsecurity.service.UserService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

/**
 * test 에 필요한 Bean 등록
 */
@TestConfiguration
@ComponentScan(
        basePackages = {
                "io.security.corespringsecurity.security",
                "io.security.corespringsecurity.configs"})
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

    public static List<Resources> getAdminResources() {
        HashSet<Role> adminRoles = new HashSet<>();
        adminRoles.add(Role.builder()
                .id(1L)
                .roleName("ROLE_ADMIN")
                .roleDesc("관리자")
                .build());
        return Arrays.asList(Resources.builder()
                        .id(4L)
                        .resourceName("/config/**")
                        .resourceType("url")
                        .orderNum(1)
                        .roleSet(adminRoles)
                        .build(),
                Resources.builder()
                        .id(7L)
                        .resourceName("/admin/**")
                        .resourceType("url")
                        .orderNum(4)
                        .roleSet(adminRoles)
                        .build());

    }
    public static Resources getMessagesResources() {
        HashSet<Role> managerRoles = new HashSet<>();
        managerRoles.add(Role.builder()
                .id(2L)
                .roleName("ROLE_MANAGER")
                .roleDesc("매니저")
                .build());
        return Resources.builder()
                .id(5L)
                .resourceName("/messages/**")
                .resourceType("url")
                .orderNum(2)
                .roleSet(managerRoles)
                .build();
    }
    public static Resources getMypageResources() {
        HashSet<Role> userRoles = new HashSet<>();
        userRoles.add(Role.builder()
                .id(3L)
                .roleName("ROLE_USER")
                .roleDesc("사용자")
                .build());
        return Resources.builder()
                .id(6L)
                .resourceName("/mypage/**")
                .resourceType("url")
                .orderNum(3)
                .roleSet(userRoles)
                .build();
    }
    public static List<Resources> getResourcesList() {
        List<Resources> resourcesList = new ArrayList<>();
        resourcesList.addAll(getAdminResources());
        resourcesList.add(getMypageResources());
        resourcesList.add(getMessagesResources());
        return resourcesList;
    }
}
