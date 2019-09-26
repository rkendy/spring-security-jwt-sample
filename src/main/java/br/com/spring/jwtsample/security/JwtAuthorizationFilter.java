package br.com.spring.jwtsample.security;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

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
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

/**
 * Filter responsible for checking if token is present in the request.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

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


    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(JwtConstants.HEADER);
        if(token != null && !token.isEmpty() && token.startsWith(JwtConstants.PREFIX)) {
            try {
                byte[] signinkey = JwtConstants.SECRET.getBytes();
                Jws<Claims> parsedToken = Jwts.parser()
                                                .setSigningKey(signinkey)
                                                .parseClaimsJws(token.replace(JwtConstants.PREFIX, ""));
                String username = parsedToken.getBody().getSubject();
                List auths = ((List<?>)parsedToken.getBody().get("rol"))
                                                    .stream()
                                                    .map(authority -> new SimpleGrantedAuthority((String)authority))
                                                    .collect(Collectors.toList());
                if(username != null && !username.isEmpty()) {
                    return new UsernamePasswordAuthenticationToken(username, null, auths);
                }
            }
            catch(Exception e) {
                System.out.println(e);
            }
        }
        return null;
    }

    // private List<String> getRoles(Jws<Claims> parsedToken) {        
    //     Object obj = parsedToken.getBody().get("rol");

    //     return ((List<String>)parsedToken.getBody().get("rol"))
    //                                                 .stream()
    //                                                 .map(authority -> new SimpleGrantedAuthority((String)authority))
    //                                                 .collect(Collectors.toList());
    // }
    
}