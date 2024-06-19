package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.common.FormLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Configuration
@EnableWebSecurity
@Order(1)
public class FormSecurityConfig {

    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    public FormSecurityConfig(UserDetailsService userDetailsService, AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource) {
        this.userDetailsService = userDetailsService;
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Bean
    public AuthenticationProvider formAuthenticationProvider(){
        return new FormAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    @Bean
    public AuthenticationSuccessHandler formAuthenticationSuccessHandler(){
        return new FormAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler formAuthenticationFailureHandler(){
        return new FormAuthenticationFailureHandler();
    }

    @Bean
    public SecurityFilterChain formSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authenticationProvider(formAuthenticationProvider())
                .authorizeHttpRequests(
                        authorize->authorize
                                .requestMatchers("/","/users","/login").permitAll()
                                .requestMatchers("/mypage").hasRole("USER")
                                .requestMatchers("/messages").hasRole("MANAGER")
                                .requestMatchers("/config").hasRole("ADMIN")
                                .anyRequest().authenticated())
                .formLogin(loginConfig->loginConfig
                        .loginPage("/login")
                        .defaultSuccessUrl("/")
                        .successHandler(formAuthenticationSuccessHandler())
                        .failureHandler(formAuthenticationFailureHandler())
                        .authenticationDetailsSource(authenticationDetailsSource)
                        .loginProcessingUrl("/login_proc")
                        .permitAll()
                )
                .exceptionHandling(handling-> handling
                        .accessDeniedHandler(accessDeniedHandler())
                        .authenticationEntryPoint(formAuthenticationEntryPoint())
                )
                .build();
    }
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public AuthenticationEntryPoint formAuthenticationEntryPoint() {
        return new FormLoginAuthenticationEntryPoint();
    }
}
