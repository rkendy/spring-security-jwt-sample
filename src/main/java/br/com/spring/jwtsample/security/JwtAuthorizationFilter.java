package br.com.spring.jwtsample.security;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;


/**
 * Filter responsible for checking if token is present in the request.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private JwtSecurityUtil jwtSecurityUtil;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /**
     * For every request, checks if token is present.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        UsernamePasswordAuthenticationToken auth = getAuthentication(request);
        if(auth == null) {
            chain.doFilter(request, response);
            return;
        }
        SecurityContextHolder.getContext().setAuthentication(auth);
        chain.doFilter(request, response);
    }


    /**
     * Check token. Exception if something goes wrong (such as token expired).
     */
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

        try {
            if(jwtSecurityUtil == null) jwtSecurityUtil = JwtSecurityUtil.getInstance(request);            
            Claims body = jwtSecurityUtil.parseToken(request);
            List<SimpleGrantedAuthority> auths = jwtSecurityUtil.getRoles(body);
            String username = jwtSecurityUtil.getUsername(body);
            return new UsernamePasswordAuthenticationToken(username, null, auths);
        }
        catch(Exception e) {
            // Log exception...
        }
        return null;
    }

}