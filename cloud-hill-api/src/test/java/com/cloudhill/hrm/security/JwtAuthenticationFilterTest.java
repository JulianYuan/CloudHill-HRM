package com.cloudhill.hrm.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JWT认证过滤器测试")
class JwtAuthenticationFilterTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String INVALID_TOKEN = "invalid.jwt.token";
    private static final String TEST_USERNAME = "testuser";
    private static final Long TEST_USER_ID = 1L;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("令牌提取与认证流程测试")
    class TokenExtractionAndAuthFlowTests {

        @Test
        @DisplayName("认证成功 - 有效Bearer令牌设置认证信息")
        void doFilterInternal_ValidBearerToken_SetsAuthentication() throws Exception {
            Set<String> roles = new HashSet<>(Arrays.asList("ADMIN", "USER"));
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(TEST_USER_ID);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(roles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNotNull(SecurityContextHolder.getContext().getAuthentication());
            assertEquals(TEST_USERNAME, SecurityContextHolder.getContext().getAuthentication().getName());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("无Authorization头 - 继续过滤器链无认证")
        void doFilterInternal_NoAuthorizationHeader_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn(null);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
            verify(jwtTokenProvider, never()).validateToken(any());
        }

        @Test
        @DisplayName("空Authorization头 - 继续过滤器链无认证")
        void doFilterInternal_EmptyAuthorizationHeader_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("非Bearer认证头 - 继续过滤器链无认证")
        void doFilterInternal_NonBearerAuthorization_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Basic " + VALID_TOKEN);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Bearer后无空格 - 继续过滤器链无认证")
        void doFilterInternal_BearerWithoutSpace_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer" + VALID_TOKEN);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Bearer后只有空格 - 继续过滤器链无认证")
        void doFilterInternal_BearerOnlySpaces_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer ");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("无效令牌 - 继续过滤器链无认证")
        void doFilterInternal_InvalidToken_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer " + INVALID_TOKEN);
            when(jwtTokenProvider.validateToken(INVALID_TOKEN)).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
            verify(jwtTokenProvider, never()).getUserIdFromToken(any());
        }
    }

    @Nested
    @DisplayName("认证流程测试")
    class AuthenticationFlowTests {

        @Test
        @DisplayName("认证成功 - 单角色用户")
        void doFilterInternal_SingleRole_SetsAuthentication() throws Exception {
            Set<String> singleRole = new HashSet<>(Arrays.asList("USER"));
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(2L);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn("simpleuser");
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(singleRole);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNotNull(SecurityContextHolder.getContext().getAuthentication());
            assertEquals("simpleuser", SecurityContextHolder.getContext().getAuthentication().getName());
        }

        @Test
        @DisplayName("认证成功 - 无角色用户")
        void doFilterInternal_NoRoles_SetsAuthentication() throws Exception {
            Set<String> noRoles = new HashSet<>();
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(3L);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn("guest");
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(noRoles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNotNull(SecurityContextHolder.getContext().getAuthentication());
            assertEquals("guest", SecurityContextHolder.getContext().getAuthentication().getName());
        }
    }

    @Nested
    @DisplayName("边界条件测试")
    class BoundaryTests {

        @Test
        @DisplayName("处理请求 - 过期令牌")
        void doFilterInternal_ExpiredToken_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer expired.token");
            when(jwtTokenProvider.validateToken("expired.token")).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("处理请求 - 格式错误的令牌")
        void doFilterInternal_MalformedToken_ContinuesWithoutAuth() throws Exception {
            when(request.getHeader("Authorization")).thenReturn("Bearer malformed");
            when(jwtTokenProvider.validateToken("malformed")).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        @DisplayName("处理请求 - 包含特殊字符的用户名")
        void doFilterInternal_SpecialCharsInUsername_SetsAuthentication() throws Exception {
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));
            String specialUsername = "user@domain.com";
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(1L);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn(specialUsername);
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(roles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNotNull(SecurityContextHolder.getContext().getAuthentication());
            assertEquals(specialUsername, SecurityContextHolder.getContext().getAuthentication().getName());
        }

        @Test
        @DisplayName("处理请求 - 中文字符用户名")
        void doFilterInternal_ChineseUsername_SetsAuthentication() throws Exception {
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));
            String chineseUsername = "张三";
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(1L);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn(chineseUsername);
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(roles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            assertNotNull(SecurityContextHolder.getContext().getAuthentication());
            assertEquals(chineseUsername, SecurityContextHolder.getContext().getAuthentication().getName());
        }

        @Test
        @DisplayName("处理请求 - 多次调用应覆盖之前的认证")
        void doFilterInternal_MultipleCalls_OverwritesPreviousAuth() throws Exception {
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));

            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(1L);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn("user1");
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(roles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
            assertEquals("user1", SecurityContextHolder.getContext().getAuthentication().getName());

            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn("user2");
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
            assertEquals("user2", SecurityContextHolder.getContext().getAuthentication().getName());
        }
    }

    @Nested
    @DisplayName("用户详情构建测试")
    class UserDetailsConstructionTests {

        @Test
        @DisplayName("构建用户详情 - 验证角色前缀")
        void doFilterInternal_RolesHaveCorrectAuthorities() throws Exception {
            Set<String> roles = new HashSet<>(Arrays.asList("ADMIN", "USER"));
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(TEST_USER_ID);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(roles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            var authentication = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(authentication);
            assertTrue(authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
            assertTrue(authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        }

        @Test
        @DisplayName("构建用户详情 - 密码为null")
        void doFilterInternal_NullPassword_SetsAuthentication() throws Exception {
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));
            when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
            when(jwtTokenProvider.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtTokenProvider.getUserIdFromToken(VALID_TOKEN)).thenReturn(TEST_USER_ID);
            when(jwtTokenProvider.getUsernameFromToken(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(jwtTokenProvider.getRolesFromToken(VALID_TOKEN)).thenReturn(roles);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            var authentication = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(authentication);
            assertNull(((CloudHillUserDetails) authentication.getPrincipal()).getPassword());
        }
    }
}
