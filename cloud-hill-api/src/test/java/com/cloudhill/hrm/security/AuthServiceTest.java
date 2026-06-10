package com.cloudhill.hrm.security;

import com.cloudhill.hrm.common.exception.BusinessException;
import com.cloudhill.hrm.modules.system.dto.LoginRequest;
import com.cloudhill.hrm.modules.system.dto.LoginResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("认证服务测试")
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private AuthService authService;

    private LoginRequest validLoginRequest;
    private CloudHillUserDetails userDetails;
    private static final String TEST_TOKEN = "test.jwt.token";

    @BeforeEach
    void setUp() {
        Set<String> roles = new HashSet<>();
        roles.add("ADMIN");
        roles.add("USER");

        userDetails = new CloudHillUserDetails(1L, "testuser", "password", roles);

        validLoginRequest = new LoginRequest();
        validLoginRequest.setUsername("testuser");
        validLoginRequest.setPassword("password123");
    }

    @Nested
    @DisplayName("认证测试")
    class AuthenticateTests {

        @Test
        @DisplayName("认证成功 - 返回有效的登录响应")
        void authenticate_Success_ReturnsLoginResponse() {
            Authentication authentication = mock(Authentication.class);
            when(authentication.getPrincipal()).thenReturn(userDetails);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);
            when(jwtTokenProvider.generateToken(1L, "testuser", userDetails.getRoles()))
                    .thenReturn(TEST_TOKEN);

            LoginResponse response = authService.authenticate(validLoginRequest);

            assertNotNull(response);
            assertEquals(1L, response.getUserId());
            assertEquals("testuser", response.getUsername());
            assertEquals(TEST_TOKEN, response.getToken());
            assertNotNull(response.getRoles());
            assertEquals(2, response.getRoles().size());
            assertTrue(response.getRoles().contains("ADMIN"));
            assertTrue(response.getRoles().contains("USER"));

            verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
            verify(jwtTokenProvider).generateToken(1L, "testuser", userDetails.getRoles());
        }

        @Test
        @DisplayName("认证成功 - 单角色用户")
        void authenticate_SingleRole_Success() {
            Set<String> singleRole = new HashSet<>();
            singleRole.add("SUPER_ADMIN");
            CloudHillUserDetails singleRoleUser = new CloudHillUserDetails(2L, "admin", "pass", singleRole);

            Authentication authentication = mock(Authentication.class);
            when(authentication.getPrincipal()).thenReturn(singleRoleUser);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);
            when(jwtTokenProvider.generateToken(2L, "admin", singleRole)).thenReturn("admin.token");

            LoginRequest request = new LoginRequest();
            request.setUsername("admin");
            request.setPassword("pass");

            LoginResponse response = authService.authenticate(request);

            assertNotNull(response);
            assertEquals(2L, response.getUserId());
            assertEquals("admin", response.getUsername());
            assertEquals(1, response.getRoles().size());
            assertTrue(response.getRoles().contains("SUPER_ADMIN"));
        }

        @Test
        @DisplayName("认证失败 - 用户名或密码错误")
        void authenticate_InvalidCredentials_ThrowsBusinessException() {
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenThrow(new BadCredentialsException("Bad credentials"));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> authService.authenticate(validLoginRequest));

            assertEquals(401, exception.getCode());
            assertEquals("用户名或密码错误", exception.getMessage());
            verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
            verify(jwtTokenProvider, never()).generateToken(anyLong(), anyString(), anySet());
        }

        @Test
        @DisplayName("认证失败 - 用户不存在")
        void authenticate_UserNotFound_ThrowsBusinessException() {
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenThrow(new AuthenticationException("User not found") {});

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> authService.authenticate(validLoginRequest));

            assertEquals(401, exception.getCode());
            assertEquals("用户名或密码错误", exception.getMessage());
        }

        @Test
        @DisplayName("认证失败 - 账户被禁用")
        void authenticate_AccountDisabled_ThrowsBusinessException() {
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenThrow(new AuthenticationException("Account is disabled") {});

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> authService.authenticate(validLoginRequest));

            assertEquals(401, exception.getCode());
        }
    }

    @Nested
    @DisplayName("边界条件测试")
    class BoundaryTests {

        @Test
        @DisplayName("认证 - 空用户名")
        void authenticate_EmptyUsername_ThrowsBusinessException() {
            LoginRequest request = new LoginRequest();
            request.setUsername("");
            request.setPassword("password");

            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenThrow(new BadCredentialsException("Empty username"));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> authService.authenticate(request));

            assertEquals(401, exception.getCode());
        }

        @Test
        @DisplayName("认证 - 空密码")
        void authenticate_EmptyPassword_ThrowsBusinessException() {
            LoginRequest request = new LoginRequest();
            request.setUsername("testuser");
            request.setPassword("");

            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenThrow(new BadCredentialsException("Empty password"));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> authService.authenticate(request));

            assertEquals(401, exception.getCode());
        }

        @Test
        @DisplayName("认证 - 无角色用户")
        void authenticate_NoRoles_Success() {
            Set<String> emptyRoles = new HashSet<>();
            CloudHillUserDetails noRoleUser = new CloudHillUserDetails(3L, "norole", "pass", emptyRoles);

            Authentication authentication = mock(Authentication.class);
            when(authentication.getPrincipal()).thenReturn(noRoleUser);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(authentication);
            when(jwtTokenProvider.generateToken(3L, "norole", emptyRoles)).thenReturn("norole.token");

            LoginRequest request = new LoginRequest();
            request.setUsername("norole");
            request.setPassword("pass");

            LoginResponse response = authService.authenticate(request);

            assertNotNull(response);
            assertEquals(3L, response.getUserId());
            assertTrue(response.getRoles().isEmpty());
        }
    }
}
