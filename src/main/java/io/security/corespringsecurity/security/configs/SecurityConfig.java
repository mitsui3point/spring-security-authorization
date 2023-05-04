package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.Collection;
import java.util.List;

/**
 * #03. 주요 아키텍쳐 이해
 *
 * {@link FilterSecurityInterceptor}(인가처리 담당 필터)
 * 	=> {@link AccessDecisionManager}(인가처리 위임)
 * 		; {@link Authentication}(인증정보; user, SecurityContext 객체 안에 있으므로 SecurityContext 를 참조함),
 * 		  {@link FilterInvocation}(요청정보; request(/user), new FilterInvocation()에 request 객체를 담아서 전달 ),
 * 		  {@link List<ConfigAttribute>}(권한정보;hasRole('USER')) 정보를 받아 인가처리를 실제 진행
 *
 * GET /user
 * 	=> {@link FilterSecurityInterceptor} : Authentication, FilterInvocation, List<ConfigAttribute> 가공
 * 	=> {@link AccessDecisionManager#decide(Authentication, Object, Collection)}(접근 결정 관리자) 구현체 내 메서드
 * 	=> voter.vote(Authentication, FilterInvocation, List<ConfigAttribute>)
 *
 * antMatchers("/messages").hasRole("MANAGER") => Map 객체에 담아두고 보관
 *  => {@link AbstractSecurityInterceptor#beforeInvocation(Object)}
 * 		(Object object => {@link FilterInvocation}; 요청정보 파라미터로 전달받음)
 * 		({@link List<ConfigAttribute>}; 권한목록 가져오기)
 * 		=> FilterInvocationSecurityMetadataSource implements ExpressionBasedFilterInvocationSecurityMetadataSource.processMap()
 * 			=> DefaultFilterInvocationSecurityMetadataSource.getAttributes(Object object)
 * 		=> Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
 *  => {@link AbstractSecurityInterceptor#beforeInvocation(Object)}
 * 		({@link Authentication}; 인증정보 가져오기)
 * 		=> authenticateIfRequired()
 * 			=> SecurityContextHolder.getContext().getAuthentication();
 * 	=> {@link AbstractSecurityInterceptor#beforeInvocation(Object)}
 * 		(최종 voter.vote(authentication, object, configAttributes) 실행)
 * 		=> this.accessDecisionManager.decide(authenticated, object, attributes);
 * 			=> voter.vote(authentication, object, configAttributes);
 *
 * 이 중 List<ConfigAttribute>; 권한목록 가져오기 를 customizing 하여 DB 연동을 시킬것임
 * => SecurityMetadataSource#Collection<ConfigAttribute> getAttributes(Object object) Override 해서 DB연동 인가처리 진행
 * 	=> {@link FilterInvocationSecurityMetadataSource}(url 기반,
 * 						 {@link ExpressionBasedFilterInvocationSecurityMetadataSource},
 * 						 {@link DefaultFilterInvocationSecurityMetadataSource})
 * 	=> {@link MethodSecurityMetadataSource}(http method 기반,
 * 						{@link Jsr250MethodSecurityMetadataSource}; @RolesAllowed("USER"),
 * 						{@link SecuredAnnotationSecurityMetadataSource}; @Secured("ROLE_USER"),
 * 						{@link PrePostAnnotationSecurityMetadataSource}; @PreAuthorize("hasRole('USER’)”) @PostAuthorize("hasRole('USER')"),
 * 						{@link MapBasedMethodSecurityMetadataSource})
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;
    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll()
        .and()
                .exceptionHandling()
//                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler())
//        .and()
//                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
        ;

        http.csrf().disable();

        customConfigurer(http);
    }

    private void customConfigurer(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                .loginProcessingUrl("/api/login")
                .setAuthenticationManager(authenticationManagerBean());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        return new FormAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider(){
        return new AjaxAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandler();
    }

    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler commonAccessDeniedHandler = new FormAccessDeniedHandler();
        commonAccessDeniedHandler.setErrorPage("/denied");
        return commonAccessDeniedHandler;
    }
}
