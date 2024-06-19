package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.common.AjaxLoginUrlAuthenticationEntryPoint;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@Order(0)
public class AjaxSecurityConfigWithDSL {
    private final UserDetailsService userDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;
    public AjaxSecurityConfigWithDSL(UserDetailsService userDetailsService, AuthenticationConfiguration authenticationConfiguration) {
        this.userDetailsService = userDetailsService;
        this.authenticationConfiguration = authenticationConfiguration;
    }

    @Bean
    public PasswordEncoder ajaxPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }
    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandler();
    }
    @Bean
    public AuthenticationEntryPoint ajaxLoginUrlAuthenticationEntryPoint(){
        return new AjaxLoginUrlAuthenticationEntryPoint();
    }
    @Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler(){
        return new AjaxAccessDeniedHandler();
    }
    @Bean
    public SecurityFilterChain ajaxSecurityFilterChain(HttpSecurity http) throws Exception {
        ProviderManager ajaxAuthenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        ajaxAuthenticationManager.getProviders().add(new AjaxAuthenticationProvider(userDetailsService, ajaxPasswordEncoder()));

        return http
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                .setAuthenticationManager(ajaxAuthenticationManager)
                .loginProcessingUrl("/api/login").and()
                .securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/login").permitAll()
                        .requestMatchers("/api/messages").hasRole("MANAGER")
                        .anyRequest().authenticated())
                .exceptionHandling(exceptionHandler -> exceptionHandler
                        .accessDeniedHandler(ajaxAccessDeniedHandler())
                        .authenticationEntryPoint(ajaxLoginUrlAuthenticationEntryPoint()))
                .csrf().disable()
                .build();
    }
}
