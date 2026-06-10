package com.cloudhill.hrm.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.cloudhill.hrm.modules.system.entity.SysUser;
import com.cloudhill.hrm.modules.system.mapper.SysUserMapper;
import com.cloudhill.hrm.modules.system.mapper.SysUserRoleMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final SysUserMapper sysUserMapper;
    private final SysUserRoleMapper sysUserRoleMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser user = sysUserMapper.selectOne(
                new LambdaQueryWrapper<SysUser>()
                        .eq(SysUser::getUsername, username)
                        .eq(SysUser::getStatus, 1)   // 仅启用状态
        );
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在或已禁用");
        }

        // 查询用户拥有的角色编码
        Set<String> roleCodes = sysUserRoleMapper.getRoleCodesByUserId(user.getId());

        // 这里自定义一个实现 UserDetails 的类（或直接用 Spring Security 的 User）
        return new CloudHillUserDetails(user.getId(), user.getUsername(),
                user.getPassword(), roleCodes);
    }
}