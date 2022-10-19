package com.whq.security.oauth.service;

import com.whq.security.oauth.user.MyUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    // 后续登录使用此方法加载用户信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MyUser result = MyUser.getUser(username);
        // 模拟的用户查询数据为明文密码，实际使用时都是加密存储，此处手动加密模拟处理
        String encode = passwordEncoder.encode(result.getPassword());
        // 用户不存在，抛出异常
        if (result == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        MyUser res = new MyUser(result.getUsername(), encode);
        return res;
    }
}
