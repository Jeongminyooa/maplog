package com.example.maplog.global.auth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {
    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "bearer";
    private static final String BEARER_PREFIX = "Bearer ";
    private final long tokenValidityMilliseconds;
    private final Key key;

    public TokenProvider(@Value("${jwt.secret}") String secretKey,
                         @Value("${jwt.token-validity-in-seconds}") long tokenValidityMilliseconds) {
        // secret key 값을 Base64로 Decode
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);

        this.tokenValidityMilliseconds = tokenValidityMilliseconds;
    }

    // Authentication 객체 권한 정보를 이용하여 토큰을 생성한다.
    public TokenDto generateToken(Authentication authentication) {
        // authorities
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // 토큰 만료 시간
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityMilliseconds);

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.ES512)
                .setExpiration(validity)
                .compact();

        String refreshToken = Jwts.builder()
                .signWith(key, SignatureAlgorithm.ES512)
                .setExpiration(validity)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .tokenValidityMilliseconds(validity.getTime())
                .refreshToken(refreshToken)
                .build();
    }

    // 토큰에 담긴 정보를 이용해 Authentication 객체 반환
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // claim을 이용해 authorities 생성
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // claim과 authorities 이용해 User 객체 생성
        UserDetails principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean validateToken(String token) {
       try {
           Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
           return true;
       } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
           /* 커스텀 에러처리 */
           log.error("잘못된 JWT 토큰 서명");
       } catch (ExpiredJwtException e) {
           log.error("만료된 JWT 토큰");
       } catch (UnsupportedJwtException e) {
           log.error("지원되지 않는 JWT 토큰");
       } catch (IllegalArgumentException e) {
           log.error("잘못된 JWT 토큰");
       }
        return false;
    }
}
