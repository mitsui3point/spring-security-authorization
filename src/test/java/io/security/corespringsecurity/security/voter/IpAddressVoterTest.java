package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.testutil.testconfig.WithMockCustomUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ExtendWith(MockitoExtension.class)
public class IpAddressVoterTest {
    MockMvc mvc;

    @MockBean
    WebAuthenticationDetails webAuthenticationDetails;

    @Autowired
    WebApplicationContext context;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    @WithMockCustomUser
    @DisplayName("IpAddressVoter 가 인가된 Ip 를 허용한다.")
    void ipAccepted() throws Exception {
        //when
        mvc.perform(MockMvcRequestBuilders
                        .get("/mypage")
                        //.with(csrf())
                )
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockCustomUser(remoteAddr = "127.0.0.1")
    @DisplayName("IpAddressVoter 가 미인가된 Ip 접근을 거부한다.")
    void ipForbidden() throws Exception {
        //when
        mvc.perform(MockMvcRequestBuilders
                        .get("/mypage"))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/denied?exception=Invalid IpAddress"));
    }

}