package com.whq.security.oauth.config;

import com.whq.security.oauth.provider.SMSAuthenticationProvider;
import com.whq.security.oauth.service.MyUserDetailsService;
import com.whq.security.oauth.service.SMSUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * spring security 相关配置
 */
@Configuration
public class WhqSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    // 短信验证时获取用户方式改变
    @Autowired
    private SMSUserDetailsService smsUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //1.配置基本认证方式
        http.authorizeRequests()
                // 角色为“ADMIN”的用户才可以访问/test/admin/相关的接口
                //.antMatchers("/test/admin/**").hasRole("ADMIN")
                // 角色为"USER"、“ADMIN”的用户才可以访问/test/user/相关的接口
                //.antMatchers("/test/user/**").hasAnyRole("USER", "ADMIN")
                // 所有用户都可以访问的接口
                .antMatchers("/swagger/**", "/oauth/token/**").permitAll()
                // 对任意请求都进行认证（其他路径的请求登录后才可以访问）
                .anyRequest()
                .authenticated()
                //开启basic认证
                .and().httpBasic()
                .and().formLogin();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 初始化security的认证管理器
    @Bean("authenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // 账号密码登录设置获取用户UserDetailsService
    // 如果所有登录方式获取用户的方式一致，则可以在AuthorizationServerConfigurerAdapter的AuthorizationServerEndpointsConfigurer中设置UserDetailsService
    @Bean
    public DaoAuthenticationProvider getDaoAuthenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(myUserDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());

        return daoAuthenticationProvider;
    }

    // 短信验证provider初始化
    @Bean
    public SMSAuthenticationProvider getSMSAuthenticationProvider(){
        SMSAuthenticationProvider smsAuthenticationProvider = new SMSAuthenticationProvider();
        smsAuthenticationProvider.setUserDetailsService(smsUserDetailsService);

        return smsAuthenticationProvider;
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(getDaoAuthenticationProvider());
        // 添加短信验证provider
        auth.authenticationProvider(getSMSAuthenticationProvider());
    }
}
