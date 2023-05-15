package io.security.corespringsecurity.testutil;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.*;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

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
                "io.security.corespringsecurity.configs",
                "io.security.corespringsecurity.service"},
        excludeFilters =
                @ComponentScan.Filter(type = FilterType.REGEX, pattern = "io.security.corespringsecurity.security.listener.*")
        )
public class TestConfig {
    @MockBean
    UserRepository userRepository;

    @MockBean
    ResourcesRepository resourcesRepository;

    @MockBean
    RoleRepository roleRepository;

    @MockBean
    RoleHierarchyRepository roleHierarchyRepository;

    @MockBean
    AccessIpRepository accessIpRepository;

    public static List<Resources> getAdminResources() {
        HashSet<Role> adminRoles = new HashSet<>();
        adminRoles.add(getAdminRole());
        return Arrays.asList(Resources.builder()
                        .resourceName("/config/**")
                        .resourceType("url")
                        .orderNum(1)
                        .roleSet(adminRoles)
                        .build(),
                Resources.builder()
                        .resourceName("/admin/**")
                        .resourceType("url")
                        .orderNum(4)
                        .roleSet(adminRoles)
                        .build());

    }

    public static Resources getMessagesResources() {
        HashSet<Role> managerRoles = new HashSet<>();
        managerRoles.add(getManagerRole());
        return Resources.builder()
                .resourceName("/messages/**")
                .resourceType("url")
                .orderNum(2)
                .roleSet(managerRoles)
                .build();
    }

    public static Resources getMypageResources() {
        HashSet<Role> userRoles = new HashSet<>();
        userRoles.add(getUserRole());
        return Resources.builder()
                .resourceName("/mypage/**")
                .resourceType("url")
                .orderNum(3)
                .roleSet(userRoles)
                .build();
    }

    public static Role getAdminRole() {
        return Role.builder()
                .roleName("ROLE_ADMIN")
                .roleDesc("관리자")
                .build();
    }

    public static Role getManagerRole() {
        return Role.builder()
                .roleName("ROLE_MANAGER")
                .roleDesc("매니저")
                .build();
    }

    public static Role getUserRole() {
        return Role.builder()
                .roleName("ROLE_USER")
                .roleDesc("사용자")
                .build();
    }

    public static List<Resources> getResourcesList() {
        List<Resources> resourcesList = new ArrayList<>();
        resourcesList.addAll(getAdminResources());
        resourcesList.add(getMypageResources());
        resourcesList.add(getMessagesResources());
        return resourcesList;
    }

    public static RoleHierarchy getRoleAdminHierarchy(RoleHierarchy parentName) {
        RoleHierarchy roleAdmin = RoleHierarchy.builder()
                .childName("ROLE_ADMIN")
                .parentName(parentName)
                .build();
        return roleAdmin;
    }
    public static RoleHierarchy getRoleManagerHierarchy(RoleHierarchy parentName) {
        RoleHierarchy roleManager = RoleHierarchy.builder()
                .childName("ROLE_MANAGER")
                .parentName(parentName)
                .build();
        return roleManager;
    }
    public static RoleHierarchy getRoleUserHierarchy(RoleHierarchy parentName) {
        RoleHierarchy roleUser = RoleHierarchy.builder()
                .childName("ROLE_USER")
                .parentName(parentName)
                .build();
        return roleUser;
    }

    public static AccessIp getAccessIp() {
        return AccessIp.builder()
                .ipAddress("0:0:0:0:0:0:0:1")
                .build();
    }

}
