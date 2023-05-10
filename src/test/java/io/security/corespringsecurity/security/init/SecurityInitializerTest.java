package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static io.security.corespringsecurity.security.init.SecurityInitializerTest.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link org.springframework.security.access.hierarchicalroles.RoleHierarchy}
 * {@link org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl}
 * <p>
 * 스프링 시큐리티 RoleHierarchy 테스트,
 */
@WebMvcTest
@Import({
        TestConfig.class,
        TestBeforeApplicationRunner.class})
public class SecurityInitializerTest {
    @Autowired
    SecurityInitializer securityInitializer;

    @Autowired
    WebApplicationContext context;

    @Autowired
    RoleHierarchyService roleHierarchyService;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin", "/config", "/mypage", "/messages"})
    @WithMockUser(roles = "ADMIN")
    @DisplayName("RoleHierarchy 적용 후 ADMIN 권한 하나를 가진 사용자가 모든 화면에 접근이 가능하다.")
    void getRoleHierarchy(String uri) throws Exception {
        //when
        mvc.perform(get(uri)).andDo(print())
                //then
                .andExpect(status().isOk());
        verify(roleHierarchyService, atMost(1)).findAllHierarchy();
    }

    @TestConfiguration
    static class TestBeforeApplicationRunner implements ApplicationRunner {
        @MockBean RoleHierarchyService roleHierarchyService;

        @Override
        public void run(ApplicationArguments args) throws Exception {
            given(roleHierarchyService.findAllHierarchy()).willReturn("ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER\n");
        }
    }
}
