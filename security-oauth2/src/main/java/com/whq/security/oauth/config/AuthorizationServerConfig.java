package com.whq.security.oauth.config;

import com.whq.security.oauth.granter.WhqTokenGranter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * spring security oauth2 相关配置
 */
@Configuration
@AllArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final TokenStore tokenStore;
    private final TokenEnhancer jwtTokenEnhancer;
    private final JwtAccessTokenConverter jwtAccessTokenConverter;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        //获取自定义tokenGranter
        TokenGranter tokenGranter = WhqTokenGranter.getTokenGranter(authenticationManager, endpoints);
        endpoints.tokenStore(tokenStore)
                .authenticationManager(authenticationManager)
                .tokenGranter(tokenGranter);
        // 扩展token返回结果
        if (jwtAccessTokenConverter != null && jwtTokenEnhancer != null) {
            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            List<TokenEnhancer> enhancerList = new ArrayList<>();
            enhancerList.add(jwtTokenEnhancer);
            enhancerList.add(jwtAccessTokenConverter);
            tokenEnhancerChain.setTokenEnhancers(enhancerList);
            // jwt增强
            endpoints.tokenEnhancer(tokenEnhancerChain).accessTokenConverter(jwtAccessTokenConverter);
        }
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 将client-secret存储在内存中
        // 如果需要从数据库加载则继承JdbcClientDetailsService类自定义处理
        // clients.withClientDetails();

        // basic验证用户名：whqClient 密码：whqSecret
        clients.inMemory().withClient("whqClient").secret(passwordEncoder.encode("whqSecret"))
                // 令牌有效时间，单位秒
                .accessTokenValiditySeconds(7200)
                // 支持短信验证码、账号密码模式登录
                .authorizedGrantTypes("refresh_token", "SMSVerification", "pwd")
                // 权限有哪些,如果这两配置了该参数，客户端发请求可以不带参数，使用配置的参数
                .scopes("all", "read", "write");
    }
}
