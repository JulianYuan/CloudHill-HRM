package com.cloudhill.hrm.config;

import com.cloudhill.hrm.common.security.XssFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     * 注册 XSS 过滤器
     */
    @Bean
    public FilterRegistrationBean<XssFilter> xssFilterRegistration() {
        FilterRegistrationBean<XssFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new XssFilter());
        registration.addUrlPatterns("/*");
        registration.setName("xssFilter");
        registration.setOrder(1);
        // 排除 Swagger 和静态资源路径，避免干扰 API 文档
        registration.addInitParameter("exclusions", "/swagger-ui/**,/v3/api-docs/**,/swagger-ui.html,/static/**,/public/**");
        return registration;
    }
}
