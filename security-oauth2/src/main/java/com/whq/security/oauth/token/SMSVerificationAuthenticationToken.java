package com.whq.security.oauth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class SMSVerificationAuthenticationToken extends AbstractAuthenticationToken {

    // 存储登录手机号
    private Object principal;

    // 存储登录短信验证码
    private Object credentials;

    public SMSVerificationAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(false);
    }

    /**
     * 校验通过时使用此构造函数
     * 设置参数super.setAuthenticated(true); 表示短信验证码登录校验通过，准备生成token
     */
    public SMSVerificationAuthenticationToken(Collection<? extends GrantedAuthority> authorities, Object principal, Object credentials) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        // 设置校验通过
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
