package com.cloudhill.hrm.common.security;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DataPermissionContext {

    private Long userId;
    private Long deptId;
    private String dataScope;

    public static final String DATA_SCOPE_ALL = "ALL";
    public static final String DATA_SCOPE_DEPT_AND_CHILD = "DEPT_AND_CHILD";
    public static final String DATA_SCOPE_SELF = "SELF";

    public boolean isAll() {
        return DATA_SCOPE_ALL.equals(dataScope);
    }

    public boolean isDeptAndChild() {
        return DATA_SCOPE_DEPT_AND_CHILD.equals(dataScope);
    }

    public boolean isSelf() {
        return DATA_SCOPE_SELF.equals(dataScope);
    }
}
