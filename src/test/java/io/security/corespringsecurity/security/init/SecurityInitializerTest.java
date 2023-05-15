package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.testutil.testconfig.WithMockCustomUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

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
@SpringBootTest
public class SecurityInitializerTest {

    @Autowired
    WebApplicationContext context;

    MockMvc mvc;

    @Autowired
    RoleHierarchyRepository roleHierarchyRepository;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin", "/config", "/mypage", "/messages"})
    @WithMockCustomUser(roles = "ADMIN")
    @DisplayName("RoleHierarchy 적용 후 ADMIN 접근허용 URI에 접근 성공한다.")
    void accessAllowAdmin(String uri) throws Exception {
        //when
        mvc.perform(get(uri)).andDo(print())
                //then
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/mypage", "/messages"})
    @WithMockCustomUser(roles = "MANAGER")
    @DisplayName("RoleHierarchy 적용 후 MANAGER 접근허용 URI에 접근 성공한다.")
    void accessAllowedManager(String uri) throws Exception {
        //when
        mvc.perform(get(uri)).andDo(print())
                //then
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin", "/config"})
    @WithMockCustomUser(roles = "MANAGER")
    @DisplayName("RoleHierarchy 적용 후 MANAGER 접근거부 URI에 접근 실패한다.")
    void accessDeniedManager(String uri) throws Exception {
        //when
        mvc.perform(get(uri)).andDo(print())
                //then
                .andExpect(status().is3xxRedirection());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/mypage"})
    @WithMockCustomUser(roles = "USER")
    @DisplayName("RoleHierarchy 적용 후 USER 접근가능 URI에 접근 성공한다.")
    void accessAllowUser(String uri) throws Exception {
        //when
        mvc.perform(get(uri)).andDo(print())
                //then
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin", "/config", "/messages"})
    @WithMockCustomUser(roles = "USER")
    @DisplayName("RoleHierarchy 적용 후 USER 접근거부 URI에 접근 실패한다.")
    void accessDeniedUser(String uri) throws Exception {
        //when
        mvc.perform(get(uri)).andDo(print())
                //then
                .andExpect(status().is3xxRedirection());
    }
}