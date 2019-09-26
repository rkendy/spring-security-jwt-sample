package br.com.spring.jwtsample.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

public class JwtConstants {
    public static String SECRET="secret.secret.secret.secret.secret.secret.secret.secret.secret.s"; // 64 chars for HS512
    public static String PREFIX="Bearer ";
    public static String HEADER="Authorization";
    public static String TYPE="JWT";
    public static String ISSUER="secure-api";
    public static String AUDIENCE="secure-app";
    public static long EXPIRATION=43200000;
}

