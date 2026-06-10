package com.cloudhill.hrm.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;
    private final long expirationMs;

    // 从配置文件读取密钥和过期时间
    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.expiration}") long expirationMs) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    /**
     * 生成 Token
     * @param userId   用户ID
     * @param username 用户名
     * @param roles    角色编码集合
     */
    public String generateToken(Long userId, String username, Set<String> roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(String.valueOf(userId))          // 主题存用户ID
                .claim("username", username)              // 自定义字段
                .claim("roles", String.join(",", roles))
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    /**
     * 从 Token 中解析用户ID
     */
    public Long getUserIdFromToken(String token) {
        Claims claims = parseTokenClaims(token);
        return Long.parseLong(claims.getSubject());
    }

    /**
     * 验证 Token 是否有效
     */
    public boolean validateToken(String token) {
        try {
            parseTokenClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 从 Token 中解析 Claims，抛出具体 JWT 异常供调用方区分处理。
     */
    public Claims parseTokenClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * 获取 Token 中的用户名
     */
    public String getUsernameFromToken(String token) {
        return (String) parseTokenClaims(token).get("username");
    }

    /**
     * 获取 Token 中的角色
     */
    public Set<String> getRolesFromToken(String token) {
        String rolesStr = (String) parseTokenClaims(token).get("roles");
        if (rolesStr == null || rolesStr.isEmpty()) {
            return new HashSet<>();
        }
        return new HashSet<>(Arrays.asList(rolesStr.split(",")));
    }
}