package br.com.spring.jwtsample.security;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtSecurityUtil {
    
    public static String PREFIX="Bearer ";
    public static String HEADER="Authorization";
    public static String TYPE="JWT";
    public static String ISSUER="secure-api";
    public static String AUDIENCE="secure-app";
    public static String ROLES_STR = "roles";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public Claims parseToken(HttpServletRequest request) {
        return parseTokenStr(request.getHeader(HEADER));
    }

    public Claims parseToken(String token) {
        return parseTokenStr(token);
    }


    public List<SimpleGrantedAuthority> getRoles(Claims body) {
        return ((List<?>)body.get(ROLES_STR))
                    .stream()
                    .map(authority -> new SimpleGrantedAuthority((String)authority))
                    .collect(Collectors.toList());   
    }

    public String getUsername(Claims body) {
        return body.getSubject();
    }

    public Date getExpirationDate(Claims body) {
        return body.getExpiration();
    }

    public Long getExpiration() {
        return expiration;
    }


    public String createToken(String username, List<String> roles) {
        return Jwts.builder()
                    .signWith(Keys.hmacShaKeyFor(secret.getBytes()),SignatureAlgorithm.HS512)
                    .setHeaderParam("typ", JwtSecurityUtil.TYPE)
                    .setIssuer(JwtSecurityUtil.ISSUER)
                    .setAudience(JwtSecurityUtil.AUDIENCE)
                    .setSubject(username)
                    .setExpiration(new Date(System.currentTimeMillis() + expiration))
                    .claim(JwtSecurityUtil.ROLES_STR, roles)
                    .compact();
    }


    private Claims parseTokenStr(String token) {
        if(token != null && !token.isEmpty() && token.startsWith(PREFIX)) {
            return getParsedToken(token).getBody();
        }
        return null;
    }


    private Jws<Claims> getParsedToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret.getBytes())
                .parseClaimsJws(token.replace(JwtSecurityUtil.PREFIX, ""));
    }

   
}

