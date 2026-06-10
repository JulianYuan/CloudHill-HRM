package com.cloudhill.hrm.common.security;

import com.cloudhill.hrm.common.annotation.RateLimit;
import com.cloudhill.hrm.common.exception.BusinessException;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("限流切面测试")
class RateLimitAspectTest {

    private RateLimitAspect rateLimitAspect;

    @Mock
    private JoinPoint joinPoint;

    @Mock
    private HttpServletRequest request;

    @Mock
    private ServletRequestAttributes requestAttributes;

    @Mock
    private MethodSignature methodSignature;

    private static final String TEST_IP = "192.168.1.100";
    private static final String TEST_METHOD_NAME = "testMethod";

    @BeforeEach
    void setUp() {
        rateLimitAspect = new RateLimitAspect();
        RequestContextHolder.setRequestAttributes(requestAttributes);
        lenient().when(requestAttributes.getRequest()).thenReturn(request);
        lenient().when(request.getRemoteAddr()).thenReturn(TEST_IP);
        lenient().when(joinPoint.getSignature()).thenReturn(methodSignature);
    }

    private RateLimit createRateLimit(String key, int count, long time, TimeUnit unit) {
        return new RateLimit() {
            @Override
            public Class<? extends java.lang.annotation.Annotation> annotationType() {
                return RateLimit.class;
            }

            @Override
            public String key() {
                return key;
            }

            @Override
            public int count() {
                return count;
            }

            @Override
            public long time() {
                return time;
            }

            @Override
            public TimeUnit unit() {
                return unit;
            }
        };
    }

    @Nested
    @DisplayName("正常限流测试")
    class NormalRateLimitTests {

        @Test
        @DisplayName("首次请求 - 不超过限制")
        void doBefore_FirstRequest_WithinLimit() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("test:", 10, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }

        @Test
        @DisplayName("多次请求 - 逐步达到限制")
        void doBefore_MultipleRequests_ProgressivelyReachingLimit() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("progressive:", 3, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
            assertEquals("请求过于频繁，请稍后再试", exception.getMessage());
        }

        @Test
        @DisplayName("不同IP独立限流")
        void doBefore_DifferentIPs_IndependentLimits() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("ip_test:", 2, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            HttpServletRequest request1 = mock(HttpServletRequest.class);
            HttpServletRequest request2 = mock(HttpServletRequest.class);
            when(request1.getRemoteAddr()).thenReturn("192.168.1.1");
            when(request2.getRemoteAddr()).thenReturn("192.168.1.2");

            ServletRequestAttributes attrs1 = mock(ServletRequestAttributes.class);
            ServletRequestAttributes attrs2 = mock(ServletRequestAttributes.class);
            when(attrs1.getRequest()).thenReturn(request1);
            when(attrs2.getRequest()).thenReturn(request2);

            RequestContextHolder.setRequestAttributes(attrs1);
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            RequestContextHolder.setRequestAttributes(attrs2);
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }

        @Test
        @DisplayName("不同方法独立限流")
        void doBefore_DifferentMethods_IndependentLimits() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("method_test:", 1, 1, TimeUnit.MINUTES);

            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod("methodA"));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());

            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod("methodB"));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }
    }

    @Nested
    @DisplayName("限流边界测试")
    class BoundaryTests {

        @Test
        @DisplayName("限制为1 - 第二次请求被拒绝")
        void doBefore_LimitOne_SecondRequestRejected() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("limit_one:", 1, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }

        @Test
        @DisplayName("限制为0 - 所有请求被拒绝")
        void doBefore_LimitZero_AllRequestsRejected() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("limit_zero:", 0, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }

        @Test
        @DisplayName("限制为负数 - 首次请求即被拒绝")
        void doBefore_NegativeLimit_FirstRequestRejected() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("negative:", -1, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }

        @Test
        @DisplayName("自定义key前缀")
        void doBefore_CustomKeyPrefix_UsesCustomKey() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("custom_prefix:", 2, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }
    }

    @Nested
    @DisplayName("时间单位测试")
    class TimeUnitTests {

        @Test
        @DisplayName("分钟为单位")
        void doBefore_MinutesUnit_WorksCorrectly() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("minutes:", 5, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            for (int i = 0; i < 5; i++) {
                assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            }

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }

        @Test
        @DisplayName("秒为单位")
        void doBefore_SecondsUnit_WorksCorrectly() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("seconds:", 3, 1, TimeUnit.SECONDS);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            for (int i = 0; i < 3; i++) {
                assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            }

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }

        @Test
        @DisplayName("毫秒为单位")
        void doBefore_MillisUnit_WorksCorrectly() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("millis:", 2, 100, TimeUnit.MILLISECONDS);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
            assertEquals(429, exception.getCode());
        }
    }

    @Nested
    @DisplayName("异常处理测试")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("RequestContextHolder无属性时正常返回")
        void doBefore_NoRequestAttributes_ReturnsWithoutException() throws NoSuchMethodException {
            RequestContextHolder.setRequestAttributes(null);
            RateLimit rateLimit = createRateLimit("test:", 10, 1, TimeUnit.MINUTES);
            when(joinPoint.getSignature()).thenReturn(methodSignature);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }

        @Test
        @DisplayName("RequestAttributes返回null时抛出NullPointerException")
        void doBefore_NullRequestFromAttributes_ThrowsNPE() throws NoSuchMethodException {
            when(requestAttributes.getRequest()).thenReturn(null);
            RateLimit rateLimit = createRateLimit("test:", 10, 1, TimeUnit.MINUTES);
            when(joinPoint.getSignature()).thenReturn(methodSignature);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertThrows(NullPointerException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }

        @Test
        @DisplayName("限流超限抛出BusinessException")
        void doBefore_LimitExceeded_ThrowsBusinessException() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("exceed:", 1, 1, TimeUnit.MINUTES);
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            BusinessException exception = assertThrows(BusinessException.class,
                    () -> rateLimitAspect.doBefore(joinPoint, rateLimit));

            assertEquals(429, exception.getCode());
            assertEquals("请求过于频繁，请稍后再试", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("IP提取测试")
    class IpExtractionTests {

        @Test
        @DisplayName("正常IP地址")
        void doBefore_NormalIP_ExtractsCorrectly() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("ip_normal:", 5, 1, TimeUnit.MINUTES);
            when(request.getRemoteAddr()).thenReturn("192.168.1.100");
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }

        @Test
        @DisplayName("IPv6地址")
        void doBefore_IPv6_ExtractsCorrectly() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("ip_v6:", 5, 1, TimeUnit.MINUTES);
            when(request.getRemoteAddr()).thenReturn("::1");
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }

        @Test
        @DisplayName("localhost地址")
        void doBefore_Localhost_ExtractsCorrectly() throws NoSuchMethodException {
            RateLimit rateLimit = createRateLimit("localhost:", 5, 1, TimeUnit.MINUTES);
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");
            when(methodSignature.getMethod()).thenReturn(TestController.class.getMethod(TEST_METHOD_NAME));

            assertDoesNotThrow(() -> rateLimitAspect.doBefore(joinPoint, rateLimit));
        }
    }

    static class TestController {
        public void testMethod() {}

        public void methodA() {}

        public void methodB() {}
    }
}
