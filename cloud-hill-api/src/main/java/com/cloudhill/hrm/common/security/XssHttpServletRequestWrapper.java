package com.cloudhill.hrm.common.security;

import cn.hutool.core.util.StrUtil;
import cn.hutool.http.HtmlUtil;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * XSS 过滤请求包装类
 */
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    public XssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return value == null ? null : HtmlUtil.filter(value);
    }

    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        return value == null ? null : HtmlUtil.filter(value);
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values != null) {
            for (int i = 0; i < values.length; i++) {
                values[i] = HtmlUtil.filter(values[i]);
            }
        }
        return values;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        // 非 JSON 请求才进行 Body 过滤（JSON 请求由 Jackson 处理或在业务层处理）
        // 这样可以避免破坏 JSON 结构，同时解决流被提前消耗的问题
        String contentType = super.getContentType();
        if (contentType != null && contentType.toLowerCase().contains("application/json")) {
            return super.getInputStream();
        }

        String body = StrUtil.str(super.getInputStream(), StandardCharsets.UTF_8);
        if (StrUtil.isBlank(body)) {
            // 如果 Body 为空，我们需要重新获取流，或者返回一个空的流
            // 注意：super.getInputStream() 已经被 StrUtil.str 读完了，不能直接返回
            return new ServletInputStream() {
                @Override
                public int read() { return -1; }
                @Override
                public boolean isFinished() { return true; }
                @Override
                public boolean isReady() { return true; }
                @Override
                public void setReadListener(ReadListener readListener) {}
            };
        }
        
        // 过滤 HTML 标签
        String filterBody = HtmlUtil.filter(body);
        final ByteArrayInputStream bais = new ByteArrayInputStream(filterBody.getBytes(StandardCharsets.UTF_8));
        
        return new ServletInputStream() {
            @Override
            public int read() {
                return bais.read();
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }
        };
    }
}
