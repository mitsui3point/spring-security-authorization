package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@WebMvcTest
@Import(TestConfig.class)
@ExtendWith(MockitoExtension.class)
public class UrlResourcesMapFactoryBeanTest {
    @InjectMocks
    UrlResourcesMapFactoryBean urlResourcesMapFactoryBean;

    @Mock
    SecurityResourceService securityResourceService;

    @BeforeEach
    void setUp() {
        urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean(securityResourceService);
    }

    @Test
    void instanceOf() {
        boolean actual = urlResourcesMapFactoryBean instanceof FactoryBean;
        assertThat(actual).isTrue();
    }

    @Test
    @DisplayName("DB로 부터 얻은 권한/자원 정보를 ResourceMap 을 스프링 빈으로 생성해서 {@link UrlFilterInvocationSecurityMetadataSource} 에 전달")
    void getObject() throws Exception {
        //given
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> expected = new LinkedHashMap<>();
        expected.put(
                new AntPathRequestMatcher("/admin/**"), Arrays.asList(
                        new SecurityConfig("ROLE_ADMIN"),
                        new SecurityConfig("ROLE_MANAGER"))
        );
        given(securityResourceService.getResourceList()).willReturn(expected);
        //when
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> actual = urlResourcesMapFactoryBean.getObject();

        //then
        assertThat(actual).isEqualTo(expected);
        verify(securityResourceService, times(1)).getResourceList();
    }
}
