package com.cloudhill.hrm.config;

import com.cloudhill.hrm.security.JwtAuthenticationFilter;
import com.cloudhill.hrm.security.SecurityExceptionHandler;
import com.cloudhill.hrm.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsServiceImpl userDetailsService;
    private final SecurityExceptionHandler securityExceptionHandler;

    // 1. 密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. 认证提供者（将 UserDetailsService 和 PasswordEncoder 绑定）
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    // 3. 暴露 AuthenticationManager Bean（关键！）
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) {
        return authConfig.getAuthenticationManager();
    }

    // 4. 安全过滤链
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults()) // 启用 CORS，使用默认配置或 CorsConfig
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny()) // 防止 Clickjacking
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")) // 基础 CSP
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 1. 登录接口
                        .requestMatchers("/api/auth/login").permitAll()

                        // 2. Actuator 健康检查 (所有端点，包括 /actuator/health)
                        .requestMatchers("/actuator/**").permitAll()

                        // 3. Swagger / SpringDoc 文档
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/v3/api-docs.yaml"
                        ).permitAll()

                        // 4. 静态资源 (如果你的前端打包进后端，或开发时需要访问)
                        .requestMatchers(
                                "/static/**",
                                "/public/**",
                                "/favicon.ico",
                                "/index.html",
                                "/*.html",
                                "/*.css",
                                "/*.js"
                        ).permitAll()

                        // 5. 错误页面 (可选，避免登录跳转干扰)
                        .requestMatchers("/error").permitAll()

                        // 6. 其他所有请求需认证
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())  // 注册认证提供者
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(securityExceptionHandler)   // 未认证 → 401
                        .accessDeniedHandler(securityExceptionHandler)        // 无权限 → 403
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}