package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import java.io.IOException;

import static org.springframework.http.HttpMethod.POST;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login", POST.name()));
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }
        AccountDto account = objectMapper.readValue(request.getReader(), AccountDto.class);
        if(StringUtils.isEmpty(account.getUsername()) || StringUtils.isEmpty(account.getPassword())){
            throw new IllegalArgumentException("Username or Password is empty");
        }
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(account.getUsername(), account.getPassword());
        Authentication authentication = getAuthenticationManager().authenticate(ajaxAuthenticationToken);
        request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", new SecurityContextImpl(authentication));
        return authentication;
    }
    private boolean isAjax(HttpServletRequest request) {
        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }
}
