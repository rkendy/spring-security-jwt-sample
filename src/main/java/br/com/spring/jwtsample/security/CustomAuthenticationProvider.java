package br.com.spring.jwtsample.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String)authentication.getPrincipal();
        String password = (String)authentication.getCredentials();       
        List<GrantedAuthority> grantedAuths = new ArrayList<>();

        // Should validate username/password here...
        // if(false) throw new BadCredentialsException("...");

        // Should verify user roles here:
        if(username.equals("admin")) {
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        return new UsernamePasswordAuthenticationToken(username, password, grantedAuths);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
    
}