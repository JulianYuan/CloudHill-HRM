package com.cloudhill.hrm.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {

    /**
     * 获取当前登录用户ID
     */
    public static Long getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CloudHillUserDetails) {
            return ((CloudHillUserDetails) auth.getPrincipal()).getUserId();
        }
        return null; // 系统执行时可能为null，调用方需处理
    }
}