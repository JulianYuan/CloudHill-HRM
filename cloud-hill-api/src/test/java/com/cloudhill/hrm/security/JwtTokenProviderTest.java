package com.cloudhill.hrm.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JWT令牌提供者测试")
class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;
    private static final String SECRET = "ThisIsAVeryLongSecretKeyForTestingJWTTokenGenerationThatIsAtLeast256BitsLong";
    private static final long EXPIRATION_MS = 3600000; // 1小时

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(SECRET, EXPIRATION_MS);
    }

    @Nested
    @DisplayName("令牌生成测试")
    class GenerateTokenTests {

        @Test
        @DisplayName("生成令牌 - 多角色用户")
        void generateToken_MultipleRoles_ReturnsValidToken() {
            Long userId = 1L;
            String username = "testuser";
            Set<String> roles = new HashSet<>(Arrays.asList("ADMIN", "USER", "MANAGER"));

            String token = jwtTokenProvider.generateToken(userId, username, roles);

            assertNotNull(token);
            assertFalse(token.isEmpty());
            assertTrue(token.split("\\.").length == 3);
        }

        @Test
        @DisplayName("生成令牌 - 单角色用户")
        void generateToken_SingleRole_ReturnsValidToken() {
            Long userId = 2L;
            String username = "admin";
            Set<String> roles = new HashSet<>(Arrays.asList("SUPER_ADMIN"));

            String token = jwtTokenProvider.generateToken(userId, username, roles);

            assertNotNull(token);
            assertTrue(jwtTokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 无角色用户")
        void generateToken_NoRoles_ReturnsValidToken() {
            Long userId = 3L;
            String username = "guest";
            Set<String> roles = new HashSet<>();

            String token = jwtTokenProvider.generateToken(userId, username, roles);

            assertNotNull(token);
            assertTrue(jwtTokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 不同用户ID产生不同令牌")
        void generateToken_DifferentUserIds_ProducesDifferentTokens() {
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));
            String token1 = jwtTokenProvider.generateToken(1L, "user1", roles);
            String token2 = jwtTokenProvider.generateToken(2L, "user2", roles);

            assertNotEquals(token1, token2);
        }

        @Test
        @DisplayName("生成令牌 - 不同用户名产生不同令牌")
        void generateToken_DifferentUsernames_ProducesDifferentTokens() {
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));
            String token1 = jwtTokenProvider.generateToken(1L, "alice", roles);
            String token2 = jwtTokenProvider.generateToken(1L, "bob", roles);

            assertNotEquals(token1, token2);
        }

        @Test
        @DisplayName("生成令牌 - 不同角色产生不同令牌")
        void generateToken_DifferentRoles_ProducesDifferentTokens() {
            String token1 = jwtTokenProvider.generateToken(1L, "user", new HashSet<>(Arrays.asList("ADMIN")));
            String token2 = jwtTokenProvider.generateToken(1L, "user", new HashSet<>(Arrays.asList("USER")));

            assertNotEquals(token1, token2);
        }
    }

    @Nested
    @DisplayName("令牌解析测试")
    class ParseTokenTests {

        @Test
        @DisplayName("解析令牌 - 获取用户ID")
        void getUserIdFromToken_ValidToken_ReturnsCorrectUserId() {
            Long expectedUserId = 12345L;
            String username = "testuser";
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));

            String token = jwtTokenProvider.generateToken(expectedUserId, username, roles);
            Long actualUserId = jwtTokenProvider.getUserIdFromToken(token);

            assertEquals(expectedUserId, actualUserId);
        }

        @Test
        @DisplayName("解析令牌 - 获取用户名")
        void getUsernameFromToken_ValidToken_ReturnsCorrectUsername() {
            Long userId = 1L;
            String expectedUsername = "john_doe";
            Set<String> roles = new HashSet<>(Arrays.asList("USER"));

            String token = jwtTokenProvider.generateToken(userId, expectedUsername, roles);
            String actualUsername = jwtTokenProvider.getUsernameFromToken(token);

            assertEquals(expectedUsername, actualUsername);
        }

        @Test
        @DisplayName("解析令牌 - 获取多角色")
        void getRolesFromToken_MultipleRoles_ReturnsAllRoles() {
            Long userId = 1L;
            String username = "admin";
            Set<String> expectedRoles = new HashSet<>(Arrays.asList("ADMIN", "SUPER_ADMIN", "MANAGER"));

            String token = jwtTokenProvider.generateToken(userId, username, expectedRoles);
            Set<String> actualRoles = jwtTokenProvider.getRolesFromToken(token);

            assertEquals(expectedRoles.size(), actualRoles.size());
            assertTrue(actualRoles.containsAll(expectedRoles));
        }

        @Test
        @DisplayName("解析令牌 - 无角色返回空集合")
        void getRolesFromToken_NoRoles_ReturnsEmptySet() {
            Long userId = 1L;
            String username = "guest";
            Set<String> roles = new HashSet<>();

            String token = jwtTokenProvider.generateToken(userId, username, roles);
            Set<String> actualRoles = jwtTokenProvider.getRolesFromToken(token);

            assertNotNull(actualRoles);
            assertTrue(actualRoles.isEmpty());
        }
    }

    @Nested
    @DisplayName("令牌验证测试")
    class ValidateTokenTests {

        @Test
        @DisplayName("验证令牌 - 有效令牌")
        void validateToken_ValidToken_ReturnsTrue() {
            String token = jwtTokenProvider.generateToken(1L, "user", new HashSet<>(Arrays.asList("USER")));

            assertTrue(jwtTokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("验证令牌 - 格式错误的令牌")
        void validateToken_MalformedToken_ReturnsFalse() {
            String malformedToken = "invalid.token.format";

            assertFalse(jwtTokenProvider.validateToken(malformedToken));
        }

        @Test
        @DisplayName("验证令牌 - 空令牌")
        void validateToken_EmptyToken_ReturnsFalse() {
            assertFalse(jwtTokenProvider.validateToken(""));
        }

        @Test
        @DisplayName("验证令牌 - null令牌")
        void validateToken_NullToken_ReturnsFalse() {
            assertFalse(jwtTokenProvider.validateToken(null));
        }

        @Test
        @DisplayName("验证令牌 - 使用错误密钥签名的令牌")
        void validateToken_WrongSecret_ReturnsFalse() {
            JwtTokenProvider otherProvider = new JwtTokenProvider(
                    "AnotherVeryLongSecretKeyForTestingThatIsAlsoAtLeast256BitsLong", EXPIRATION_MS);
            String tokenWithOtherSecret = otherProvider.generateToken(1L, "user", new HashSet<>());

            assertFalse(jwtTokenProvider.validateToken(tokenWithOtherSecret));
        }

        @Test
        @DisplayName("验证令牌 - 完全伪造的令牌")
        void validateToken_ForgedToken_ReturnsFalse() {
            String forgedToken = Base64.getEncoder()
                    .encodeToString("{\"sub\":\"1\",\"username\":\"admin\",\"roles\":\"ADMIN\"}".getBytes(StandardCharsets.UTF_8));

            assertFalse(jwtTokenProvider.validateToken(forgedToken));
        }
    }

    @Nested
    @DisplayName("过期令牌测试")
    class ExpiredTokenTests {

        @Test
        @DisplayName("生成过期令牌 - 短期过期")
        void generateToken_ShortExpiration_ExpiredToken() {
            JwtTokenProvider shortExpiryProvider = new JwtTokenProvider(SECRET, 1);
            String token = shortExpiryProvider.generateToken(1L, "user", new HashSet<>());

            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            assertFalse(shortExpiryProvider.validateToken(token));
        }
    }

    @Nested
    @DisplayName("边界条件测试")
    class BoundaryTests {

        @Test
        @DisplayName("生成令牌 - 用户ID为0")
        void generateToken_UserIdZero_Success() {
            String token = jwtTokenProvider.generateToken(0L, "user", new HashSet<>(Arrays.asList("USER")));

            assertTrue(jwtTokenProvider.validateToken(token));
            assertEquals(0L, jwtTokenProvider.getUserIdFromToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 用户ID为负数")
        void generateToken_NegativeUserId_Success() {
            String token = jwtTokenProvider.generateToken(-1L, "user", new HashSet<>(Arrays.asList("USER")));

            assertTrue(jwtTokenProvider.validateToken(token));
            assertEquals(-1L, jwtTokenProvider.getUserIdFromToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 用户名包含特殊字符")
        void generateToken_SpecialCharactersInUsername_Success() {
            String username = "user@domain.com";
            String token = jwtTokenProvider.generateToken(1L, username, new HashSet<>(Arrays.asList("USER")));

            assertTrue(jwtTokenProvider.validateToken(token));
            assertEquals(username, jwtTokenProvider.getUsernameFromToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 用户名包含中文字符")
        void generateToken_ChineseUsername_Success() {
            String username = "张三";
            String token = jwtTokenProvider.generateToken(1L, username, new HashSet<>(Arrays.asList("USER")));

            assertTrue(jwtTokenProvider.validateToken(token));
            assertEquals(username, jwtTokenProvider.getUsernameFromToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 超长用户名")
        void generateToken_LongUsername_Success() {
            String username = "a".repeat(1000);
            String token = jwtTokenProvider.generateToken(1L, username, new HashSet<>(Arrays.asList("USER")));

            assertTrue(jwtTokenProvider.validateToken(token));
            assertEquals(username, jwtTokenProvider.getUsernameFromToken(token));
        }

        @Test
        @DisplayName("生成令牌 - 超多角色")
        void generateToken_ManyRoles_Success() {
            Set<String> manyRoles = new HashSet<>();
            for (int i = 0; i < 100; i++) {
                manyRoles.add("ROLE_" + i);
            }
            String token = jwtTokenProvider.generateToken(1L, "user", manyRoles);

            assertTrue(jwtTokenProvider.validateToken(token));
            Set<String> actualRoles = jwtTokenProvider.getRolesFromToken(token);
            assertEquals(100, actualRoles.size());
        }

        @Test
        @DisplayName("获取角色 - 角色字符串为空")
        void getRolesFromToken_EmptyRolesString_ReturnsEmptySet() {
            Long userId = 1L;
            String username = "user";
            Set<String> roles = new HashSet<>();

            String token = jwtTokenProvider.generateToken(userId, username, roles);
            Set<String> actualRoles = jwtTokenProvider.getRolesFromToken(token);

            assertNotNull(actualRoles);
            assertTrue(actualRoles.isEmpty());
        }
    }
}
