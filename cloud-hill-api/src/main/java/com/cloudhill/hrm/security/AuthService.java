package com.cloudhill.hrm.security;

import com.cloudhill.hrm.common.exception.BusinessException;
import com.cloudhill.hrm.modules.system.dto.LoginRequest;
import com.cloudhill.hrm.modules.system.dto.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public LoginResponse authenticate(LoginRequest request) throws BusinessException {
        try {
            // 使用 Spring Security 的认证管理器进行验证
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            CloudHillUserDetails userDetails = (CloudHillUserDetails) authentication.getPrincipal();
            String token = jwtTokenProvider.generateToken(
                    userDetails.getUserId(),
                    userDetails.getUsername(),
                    userDetails.getRoles()
            );

            return new LoginResponse(userDetails.getUserId(), token, userDetails.getUsername(), userDetails.getRoles());
        } catch (AuthenticationException e) {
            throw new BusinessException(401, "用户名或密码错误");
        }
    }
}