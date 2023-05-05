package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

@WebMvcTest
@Import(TestConfig.class)
@ExtendWith(MockitoExtension.class)
public class SecurityResourceServiceTest {

    @Autowired
    ApplicationContext context;

    @Autowired
    @InjectMocks
    SecurityResourceService securityResourceService;

    @Autowired
    ResourcesRepository resourcesRepository;
    private Set<Role> roleSet = new HashSet<>();
    private Resources resources;

    @BeforeEach
    void setUp() {
        roleSet.addAll(
                Arrays.asList(
                        Role.builder()
                                .id(1L)
                                .roleName("ROLE_ADMIN")
                                .roleDesc("관리자")
                                .build(),
                        Role.builder()
                                .id(2L)
                                .roleName("ROLE_MANAGER")
                                .roleDesc("매니저권한")
                                .build()
                ));
        resources = Resources.builder()
                .resourceName("/admin/**")
                .resourceType("url")
                .orderNum(1)
                .roleSet(roleSet)
                .build();
    }

    @Test
    @DisplayName("리소스 목록 추출한다.")
    void getResourceList() {
        //given
        given(resourcesRepository.findAllResources()).willReturn(Arrays.asList(resources));
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> expected = new LinkedHashMap<>();
        expected.put(
                new AntPathRequestMatcher("/admin/**"), Arrays.asList(
                new SecurityConfig("ROLE_ADMIN"),
                new SecurityConfig("ROLE_MANAGER"))
        );
        //when
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> actual = securityResourceService.getResourceList();
        //then
        assertThat(actual).isEqualTo(expected);
    }
}
