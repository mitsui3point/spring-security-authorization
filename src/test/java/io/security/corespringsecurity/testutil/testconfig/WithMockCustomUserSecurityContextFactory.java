package io.security.corespringsecurity.testutil.testconfig;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * to customize {@link org.springframework.security.test.context.support.WithMockUserSecurityContextFactory}
 */
public class WithMockCustomUserSecurityContextFactory implements WithSecurityContextFactory<WithMockCustomUser> {

    @Override
    public SecurityContext createSecurityContext(WithMockCustomUser user) {
        String username = StringUtils.hasLength(user.username()) ? user
                .username() : user.value();
        if (username == null) {
            throw new IllegalArgumentException(user
                    + " cannot have null username on both username and value properties");
        }

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : user.authorities()) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority));
        }

        if (grantedAuthorities.isEmpty()) {
            for (String role : user.roles()) {
                if (role.startsWith("ROLE_")) {
                    throw new IllegalArgumentException("roles cannot start with ROLE_ Got "
                            + role);
                }
                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        } else if (!(user.roles().length == 1 && "USER".equals(user.roles()[0]))) {
            throw new IllegalStateException("You cannot define roles attribute "+ Arrays.asList(user.roles())+" with authorities attribute "+ Arrays.asList(user.authorities()));
        }

        User principal = new User(username, user.password(), true, true, true, true,
                grantedAuthorities);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                principal, principal.getPassword(), principal.getAuthorities());

        //added details
        MockHttpServletRequest mockRequest = new MockHttpServletRequest("", "");
        mockRequest.setRemoteAddr(user.remoteAddr());
        authentication.setDetails(new WebAuthenticationDetails(mockRequest));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
