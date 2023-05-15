package io.security.corespringsecurity.security.filter;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.testutil.testconfig.WithAnonymousCustomUser;
import io.security.corespringsecurity.testutil.testconfig.WithMockCustomUser;
import io.security.corespringsecurity.service.SecurityResourceService;
import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.*;

import static io.security.corespringsecurity.testutil.TestConfig.getResourcesList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link FilterSecurityInterceptor#doFilter(ServletRequest, ServletResponse, FilterChain)}
 * => {@link FilterSecurityInterceptor#invoke(FilterInvocation)}
 * => InterceptorStatusToken token = super.beforeInvocation(fi);
 * => {@link AbstractSecurityInterceptor#beforeInvocation(Object)}
 * <p>
 * => (이 사이에 {@link PermitAllFilter} 로직을 작성하여
 * => Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource()
 * .getAttributes(object); 로직을 호출하지 않도록 하기 위한 Filter
 * <p>
 * => {@link UrlFilterInvocationSecurityMetadataSource#getAttributes(Object)}
 * => List<ConfigAttribute> => ? null; 권한심사 없이 바로 통과
 * => ? not null;	{@link AccessDecisionManager#decide(Authentication, Object, Collection)}
 * =>			{@link AffirmativeBased#decide(Authentication, Object, Collection)} => int result = voter.vote(authentication, object, configAttributes);
 */
@WebMvcTest
@Import(TestConfig.class)
@ExtendWith(MockitoExtension.class)
public class PermitAllFilterTest {

    @Autowired
    WebApplicationContext context;

    MockMvc mvc;

    @Autowired
    @InjectMocks
    SecurityResourceService securityResourceService;

    @Autowired
    ResourcesRepository resourcesRepository;

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
        //given
        given(resourcesRepository.findAllResources()).willReturn(getResourcesList());
    }

    @ParameterizedTest
    @DisplayName("PermitAllFilter 적용 후 인증, 인가와 상관없이 접근가능한 페이지들을 접근할 수 있다.")
    @WithAnonymousUser
    @ValueSource(strings = {
            "/", "/login", "/users", /*"/denied",*/
            "/css/base.css", "/images/springsecurity.jpg", "/js/bootstrap.min.js" //ignore page ignore
    })
    void permitPage(String uri) throws Exception {
        //when
        mvc.perform(get(uri))
                .andDo(print())
                //then
                .andExpect(status().isOk())
        ;
    }

    @ParameterizedTest
    @DisplayName("PermitAllFilter 적용 후 인증, 인가가 필요한 페이지들은 접근할 수 없다.(로그인 페이지로 REDIRECT)")
    @WithAnonymousCustomUser
    @ValueSource(strings = {"/mypage", "/config", "/admin", "/messages"})
    void notPermittedPage(String uri) throws Exception {

        //when
        mvc.perform(get(uri))
                .andDo(print())
                //then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }
}
