package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private final SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    /**
     * ip 심의 실제 구현 메서드
     *
     * @param authentication the caller making the invocation(인증정보)
     * @param object         the secured object being invoked(요청정보 {@link FilterInvocation})
     * @param attributes     the configuration attributes associated with the secured object(권한정보)
     * @return
     */
    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        boolean matchedAddress = securityResourceService.getAcceptIpList()
                .stream()
                .filter(o -> o.equals(remoteAddress))
                .findFirst()
                .isPresent();

        //목록에 없음
        if (!matchedAddress) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        //목록에서 찾음
        return ACCESS_ABSTAIN;
    }
}
