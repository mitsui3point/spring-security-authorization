package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.service.SecurityResourceService;
import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@WebMvcTest
@Import(TestConfig.class)
public class UrlFilterInvocationSecurityMetadataSourceTest {
//    @Autowired
//    @InjectMocks
    UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource;

    @InjectMocks
    @Autowired
    UrlResourcesMapFactoryBean urlResourcesMapFactoryBean;

    @MockBean
    SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;

    @BeforeEach
    void setUp() throws Exception {
        requestMap = new LinkedHashMap<>();
        requestMap.put(
                new AntPathRequestMatcher("/mypage"), Arrays.asList(
                        new SecurityConfig("ROLE_USER"))
        );
        given(securityResourceService.getResourceList()).willReturn(requestMap);
        urlFilterInvocationSecurityMetadataSource = new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean.getObject());
    }

    @Test
    void instanceOf() {
        boolean actual = urlFilterInvocationSecurityMetadataSource instanceof FilterInvocationSecurityMetadataSource;
        assertThat(actual).isTrue();
    }

    @Test
    @DisplayName("getAttributes() 파라미터 캐스팅 실패한다.")
    void getAttributesParameterCastingFail() {
        assertThatThrownBy(() -> {
            urlFilterInvocationSecurityMetadataSource.getAttributes(new Object());
        }).isInstanceOf(ClassCastException.class);
    }

    @Test
    @DisplayName("GET /mypage 로 getAttributes() 호출시 ROLE_USER 권한을 반환한다.")
    void getAttributes() throws Exception {
        //when
        List<ConfigAttribute> actual = (List<ConfigAttribute>) urlFilterInvocationSecurityMetadataSource.getAttributes(
                new FilterInvocation("/mypage", HttpMethod.GET.name()));
        //then
        assertThat(actual).contains(new SecurityConfig("ROLE_USER"));
    }
}
