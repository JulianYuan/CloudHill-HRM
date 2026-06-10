package com.cloudhill.hrm.security;

import com.cloudhill.hrm.common.result.Result;
import com.cloudhill.hrm.common.result.ResultCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 统一处理 Spring Security 过滤器层的认证/授权异常，返回 JSON 格式响应。
 * <p>
 * 注意：这里的异常发生在过滤器链中，不会到达 {@code @RestControllerAdvice}，
 * 因此必须通过 {@link AuthenticationEntryPoint} 和 {@link AccessDeniedHandler} 来返回。
 * </p>
 */
@Component
@RequiredArgsConstructor
public class SecurityExceptionHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    /**
     * 未认证（无 token / token 无效 / token 过期）
     * → HTTP 401
     * <p>
     * 优先读取 request attribute 中由 JwtAuthenticationFilter 设置的
     * 具体错误消息；若无，则返回默认消息。
     * </p>
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        String jwtError = (String) request.getAttribute("jwt_error");
        Result<?> result = jwtError != null
                ? Result.error(ResultCode.UNAUTHORIZED, jwtError)
                : Result.error(ResultCode.UNAUTHORIZED);

        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 已认证但无权限（角色/权限不足）
     * → HTTP 403
     */
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(
                Result.error(ResultCode.FORBIDDEN)
        ));
    }
}