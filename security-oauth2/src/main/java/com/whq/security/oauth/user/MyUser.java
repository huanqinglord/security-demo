package com.whq.security.oauth.user;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * 用户信息实体类，实际项目中根据自身项目需求修改
 */
@Getter
@Setter
public class MyUser extends User {
    /**
     * 用户id
     */
    private final Long userId;
    /**
     * 租户ID
     */
    private final String tenantId;


    // 用户构造函数
    public MyUser(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities, Long userId, String tenantId) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.userId = userId;
        this.tenantId = tenantId;
    }

    /**
     * 方便测试用的构造函数
     * 除用户名及密码外其他信息一致
     */
    public MyUser(String username, String password) {
        // authorities 参数为用户角色相关，如果没有使用spring security进行角色权限控制，则不需要配置此参数
        this(username, password, true, true, true, true,
                AuthorityUtils.commaSeparatedStringToAuthorityList("USER,AMDIN"), 1L, "000000");
    }

    // 模拟数据库存储的用户信息
    public static Map<String, MyUser> myUsers;

    static {
        myUsers = new HashMap<>();
        myUsers.put("whq1", new MyUser("whq1", "123"));
        myUsers.put("whq2", new MyUser("whq2", "123"));
        myUsers.put("18788888888", new MyUser("whq1", "123"));
        myUsers.put("18666666666", new MyUser("whq2", "123"));
    }

    // 模拟数据库通过用户名查询用户信息
    public static MyUser getUser(String userName) {
        return myUsers.get(userName);
    }

    // 模拟数据库通过手机号查询用户信息
    public static MyUser getUserByPhone(String userName) {
        return myUsers.get(userName);
    }
}
