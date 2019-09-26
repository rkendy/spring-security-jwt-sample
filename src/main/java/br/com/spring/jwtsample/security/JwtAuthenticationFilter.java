package br.com.spring.jwtsample.security;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * Filter responsible for intercepting login, delegating authentication, and generating JWT token.
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authManager;

    /**
     * Configuration of interception
     */
    public JwtAuthenticationFilter(AuthenticationManager authManager) {
        this.authManager = authManager;
        setFilterProcessesUrl("/login");
    }

    /**
     * Getting input (username and password) and delegating authentication.
     * In our case, CustomAuthenticationProvider.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
        return authManager.authenticate(authToken);
    }

    /**
     * Generating token and setting in the response Header.
     */
    @Override
    protected void successfulAuthentication(
        HttpServletRequest request, HttpServletResponse response, 
        FilterChain filterChain, 
        Authentication authentication) {

        String username = (String)authentication.getPrincipal();
        List<String> roles = authentication.getAuthorities()
                                            .stream()
                                            .map(GrantedAuthority::getAuthority)
                                            .collect(Collectors.toList());
        
        byte[] signinKey = JwtConstants.SECRET.getBytes();
        String token = Jwts.builder()
                            .signWith(Keys.hmacShaKeyFor(signinKey),SignatureAlgorithm.HS512)
                            .setHeaderParam("typ", JwtConstants.TYPE)
                            .setIssuer(JwtConstants.ISSUER)
                            .setAudience(JwtConstants.AUDIENCE)
                            .setSubject(username)
                            .setExpiration(new Date(System.currentTimeMillis() + JwtConstants.EXPIRATION))
                            .claim(JwtConstants.ROLES_STR, roles)
                            .compact();

        response.setHeader(JwtConstants.HEADER, JwtConstants.PREFIX + token);
    }
    
}