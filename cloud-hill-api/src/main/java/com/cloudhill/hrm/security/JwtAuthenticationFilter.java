package com.cloudhill.hrm.security;

import com.cloudhill.hrm.common.result.Result;
import com.cloudhill.hrm.common.result.ResultCode;
import com.cloudhill.hrm.modules.system.entity.SysUser;
import com.cloudhill.hrm.modules.system.mapper.SysUserMapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String JWT_ERROR_ATTR = "jwt_error";

    private final JwtTokenProvider jwtTokenProvider;
    private final SysUserMapper sysUserMapper;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String bearerToken = request.getHeader("Authorization");

        // 1. 无 Authorization 头
        if (!StringUtils.hasText(bearerToken)) {
            request.setAttribute(JWT_ERROR_ATTR, "未提供认证令牌");
            chain.doFilter(request, response);
            return;
        }

        // 2. 非 Bearer 前缀
        if (!bearerToken.startsWith("Bearer ")) {
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌格式错误");
            chain.doFilter(request, response);
            return;
        }

        String token = bearerToken.substring(7);

        // 3. Bearer 后无有效字符串
        if (!StringUtils.hasText(token)) {
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌不能为空");
            chain.doFilter(request, response);
            return;
        }

        // 4. 解析 JWT，捕获具体异常
        Claims claims;
        try {
            claims = jwtTokenProvider.parseTokenClaims(token);
        } catch (ExpiredJwtException e) {
            log.warn("JWT expired: {}", e.getMessage());
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌已过期");
            chain.doFilter(request, response);
            return;
        } catch (SignatureException e) {
            log.warn("JWT signature invalid: {}", e.getMessage());
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌签名无效");
            chain.doFilter(request, response);
            return;
        } catch (MalformedJwtException e) {
            log.warn("JWT malformed: {}", e.getMessage());
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌格式无效");
            chain.doFilter(request, response);
            return;
        } catch (UnsupportedJwtException e) {
            log.warn("JWT unsupported: {}", e.getMessage());
            request.setAttribute(JWT_ERROR_ATTR, "不支持的认证令牌");
            chain.doFilter(request, response);
            return;
        } catch (IllegalArgumentException e) {
            log.warn("JWT illegal argument: {}", e.getMessage());
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌不能为空");
            chain.doFilter(request, response);
            return;
        } catch (JwtException e) {
            log.warn("JWT invalid: {}", e.getMessage());
            request.setAttribute(JWT_ERROR_ATTR, "认证令牌无效");
            chain.doFilter(request, response);
            return;
        }

        Long userId = Long.parseLong(claims.getSubject());

        // 5. 检查账号状态（禁用 → 403）
        SysUser user = sysUserMapper.selectById(userId);
        if (user == null || user.getStatus() == 0) {
            log.warn("Account disabled or not found: userId={}", userId);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(
                    Result.error(ResultCode.FORBIDDEN, "账号已被禁用")
            ));
            return;
        }

        // 6. Token 有效 + 账号正常 → 设置认证上下文
        String username = claims.get("username", String.class);
        String rolesStr = claims.get("roles", String.class);
        Set<String> roles = jwtTokenProvider.getRolesFromToken(token);

        CloudHillUserDetails userDetails = new CloudHillUserDetails(userId, username, null, roles);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        chain.doFilter(request, response);
    }
}