package io.security.corespringsecurity.testutil.testconfig;

import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * to customize {@link WithAnonymousUser}
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithAnonymousUserSecurityContextCustomFactory.class)
public @interface WithAnonymousCustomUser {
    String remoteAddr() default "0:0:0:0:0:0:0:1";
}
