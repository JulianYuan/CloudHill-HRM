package com.cloudhill.hrm.common.result;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ResultCode {
    SUCCESS(200, "操作成功"),
    BAD_REQUEST(400, "业务异常"),
    UNAUTHORIZED(401, "未授权"),
    FORBIDDEN(403, "权限不足"),
    NOT_FOUND(404, "资源不存在"),
    CONFLICT(409, "数据冲突"),
    METHOD_NOT_ALLOWED(405, "请求方法不支持"),
    VALIDATE_FAILED(412, "参数校验失败"),
    ERROR(500, "服务器内部错误");

    private final Integer code;
    private final String message;
}
