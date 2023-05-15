package io.security.corespringsecurity.testutil.testconfig;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.List;

/**
 * to customize {@link org.springframework.security.test.context.support.WithAnonymousUserSecurityContextFactory}
 */
public class WithAnonymousUserSecurityContextCustomFactory implements WithSecurityContextFactory<WithAnonymousCustomUser> {
    @Override
    public SecurityContext createSecurityContext(WithAnonymousCustomUser user) {
        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
        AnonymousAuthenticationToken authentication = new AnonymousAuthenticationToken("key", "anonymous", authorities);

        //added details
        MockHttpServletRequest mockRequest = new MockHttpServletRequest("", "");
        mockRequest.setRemoteAddr(user.remoteAddr());
        authentication.setDetails(new WebAuthenticationDetails(mockRequest));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}