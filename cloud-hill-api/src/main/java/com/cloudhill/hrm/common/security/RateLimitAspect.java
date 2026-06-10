package com.cloudhill.hrm.common.security;

import cn.hutool.cache.CacheUtil;
import cn.hutool.cache.impl.TimedCache;
import com.cloudhill.hrm.common.annotation.RateLimit;
import com.cloudhill.hrm.common.exception.BusinessException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 限流切面 (使用 Hutool TimedCache 实现简单的应用内限流)
 */
@Slf4j
// @Aspect
// @Component
public class RateLimitAspect {

    // 使用 Hutool 的本地缓存存储限流计数，设置过期时间
    private static final TimedCache<String, AtomicInteger> CACHE = CacheUtil.newTimedCache(60000);

    static {
        // 启动定时清理过期数据任务
        CACHE.schedulePrune(1000);
    }

    @Before("@annotation(rateLimit)")
    public void doBefore(JoinPoint point, RateLimit rateLimit) {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) return;
        
        HttpServletRequest request = attributes.getRequest();
        MethodSignature signature = (MethodSignature) point.getSignature();
        Method method = signature.getMethod();

        String ip = request.getRemoteAddr();
        String key = rateLimit.key() + method.getName() + ":" + ip;

        AtomicInteger counter = CACHE.get(key, false);
        if (counter == null) {
            counter = new AtomicInteger(0);
            CACHE.put(key, counter, rateLimit.unit().toMillis(rateLimit.time()));
        }

        if (counter.incrementAndGet() > rateLimit.count()) {
            log.warn("Rate limit exceeded for IP: {} on method: {}", ip, method.getName());
            throw new BusinessException(429, "请求过于频繁，请稍后再试");
        }
    }
}
