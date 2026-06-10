package com.cloudhill.hrm.security;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public class CloudHillUserDetails implements UserDetails {

    private final Long userId;
    private final String username;
    private final String password;
    private final Set<String> roles; // 角色编码，如 ROLE_SUPER_ADMIN

    public CloudHillUserDetails(Long userId, String username, String password, Set<String> roles) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 角色编码遵循 Spring Security 规范，前面加 ROLE_ 前缀（如果你的角色码没加，这里加上）
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}