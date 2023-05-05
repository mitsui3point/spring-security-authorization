package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.testutil.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@AutoConfigureMockMvc
@Import(TestConfig.class)
public class UrlFilterInvocationSecurityMetadataSourceTest {
    @Autowired
    UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource;


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
    void getAttributes() {
        //given
        FilterInvocation filterInvocation = new FilterInvocation("/mypage", HttpMethod.GET.name());
        //when
        List<ConfigAttribute> actual = (List<ConfigAttribute>) urlFilterInvocationSecurityMetadataSource.getAttributes(filterInvocation);
        //then
        assertThat(actual).contains(new SecurityConfig("ROLE_USER"));
    }
}
