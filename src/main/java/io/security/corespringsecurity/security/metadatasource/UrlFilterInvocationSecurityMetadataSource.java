package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * 사용자가 접근하고자 하는 Url 자원에 대한 권한 정보 추출
 * {@link AccessDecisionManager} 에게 전달하여 인가처리 수행
 * DB 로부터 자원 및 권한 정보를 매핑하여 맵으로 관리
 * 사용자의 매 요청마다 요청정보에 매핑된 권한 정보 확인
 */
@RequiredArgsConstructor
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private final SecurityResourceService securityResourceService;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        if (isWebStaticResources(request.getRequestURI())) {
            return null;
        }

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : getConfigAttributes().entrySet()) {
            if (entry.getKey().matches(request)) {
                return entry.getValue();
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : getConfigAttributes().entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getConfigAttributes() {
        try {
            return securityResourceService.getResourceList();
        } catch (Exception e) {
            throw new RuntimeException("User Authorizations not found", e);
        }
    }

    private boolean isWebStaticResources(String uri) {
        return uri.startsWith("/css") ||
                uri.startsWith("/images") ||
                uri.startsWith("/js");
    }
}