package io.security.corespringsecurity.testutil.testconfig;

import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * to customize {@link WithMockUser}
 */
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockCustomUserSecurityContextFactory.class)
public @interface WithMockCustomUser {

    String value() default "user";
    String username() default "user";
    String name() default "user";
    String password() default "pass";
    String[] roles() default {"USER"};
    String[] authorities() default {};
    String remoteAddr() default "0:0:0:0:0:0:0:1";
}