package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.testutil.TestConfig;
import io.security.corespringsecurity.testutil.testconfig.WithAnonymousCustomUser;
import io.security.corespringsecurity.testutil.testconfig.WithMockCustomUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
public class AopSecurityControllerTest {

    MockMvc mvc;

    @Autowired
    private WebApplicationContext context;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    @WithMockCustomUser(username = "user", password = "pass", roles = {"USER"})
    void preAuthorizeUser() throws Exception {
        //when
        mvc.perform(get("/preAuthorize").param("username", "user"))
                .andDo(print())
                //then
                .andExpect(status().isOk())
                .andExpect(view().name("aop/method"))
                .andExpect(model().attribute("method", "Success @PreAuthorize"))
        ;
    }

    @Test
    @WithAnonymousCustomUser
    void preAuthorizeAnonymousFail() throws Exception {
        //when
        mvc.perform(get("/preAuthorize"))
                .andDo(print())
                //then
                .andExpect(status().is3xxRedirection())
        ;
    }

    @Test
    @WithMockCustomUser(username = "manager", roles = "MANAGER")
    void preAuthorizeManagerFail() throws Exception {
        //when
        mvc.perform(get("/preAuthorize"))
                .andDo(print())
                //then
                .andExpect(status().is3xxRedirection())
        ;
    }
}
