package com.cloudhill.hrm.common.annotation;

import java.lang.annotation.*;
import java.util.concurrent.TimeUnit;

/**
 * 接口限流注解
 * 默认1分钟内最大请求10次
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    /**
     * 限流 key 的前缀
     */
    String key() default "rate_limit:";

    /**
     * 时间窗口内的最大请求次数，默认10次
     */
    int count() default 10;

    /**
     * 时间窗口大小，默认为1
     */
    long time() default 1;

    /**
     * 时间单位 (默认为分钟)
     */
    TimeUnit unit() default TimeUnit.MINUTES;
}
