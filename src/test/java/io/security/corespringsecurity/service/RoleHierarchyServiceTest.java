package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.impl.RoleHierarchyServiceImpl;
import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import java.util.Arrays;

import static io.security.corespringsecurity.testutil.TestConfig.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@WebMvcTest
@Import(TestConfig.class)
@ExtendWith(MockitoExtension.class)
public class RoleHierarchyServiceTest {
    @Autowired
    @InjectMocks
    RoleHierarchyServiceImpl roleHierarchyService;

    @Autowired
    //@Mock
    RoleHierarchyRepository roleHierarchyRepository;

    @Test
    @DisplayName("RoleHierarchyService Type RoleHierarchyServiceImpl")
    void instanceOf() {
        boolean actual = roleHierarchyService instanceof RoleHierarchyServiceImpl;
        assertThat(actual).isTrue();
    }

    @Test
    @DisplayName("모든 권한의 계층을 String 타입으로 출력한다.")
    void findAllHierarchy() {
        //given
        RoleHierarchy roleAdmin = getRoleAdminHierarchy(null);
        RoleHierarchy roleManager = getRoleManagerHierarchy(roleAdmin);
        RoleHierarchy roleUser = getRoleUserHierarchy(roleManager);
        given(roleHierarchyRepository.findAll()).willReturn(Arrays.asList(roleAdmin, roleManager, roleUser));
        String expected = "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER\n";
        //when
        String actual = roleHierarchyService.findAllHierarchy();
        //then
        verify(roleHierarchyRepository, times(1)).findAll();
        assertThat(actual).isEqualTo(expected);
    }
}
