package com.cloudhill.hrm.common.security;

import org.springframework.util.AntPathMatcher;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * XSS 过滤器
 */
public class XssFilter implements Filter {

    private List<String> exclusions = new ArrayList<>();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    public void init(FilterConfig filterConfig) {
        String exclusionParam = filterConfig.getInitParameter("exclusions");
        if (exclusionParam != null && !exclusionParam.isEmpty()) {
            exclusions = Arrays.asList(exclusionParam.split(","));
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String path = req.getServletPath();
        
        // 检查是否需要排除该路径
        if (isExcluded(path)) {
            chain.doFilter(request, response);
            return;
        }
        
        chain.doFilter(new XssHttpServletRequestWrapper(req), response);
    }

    private boolean isExcluded(String path) {
        if (exclusions == null || exclusions.isEmpty()) {
            return false;
        }
        for (String exclusion : exclusions) {
            if (pathMatcher.match(exclusion, path)) {
                return true;
            }
        }
        return false;
    }
}
