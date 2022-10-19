package com.whq.security.oauth.config;


import com.whq.security.oauth.factory.JwtTokenEnhancer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * jwt 生成token相关配置
 */
@Configuration
public class JwtTokenStoreConfiguration {

	/**
	 * 使用jwtTokenStore存储token
	 */
	@Bean
	public TokenStore jwtTokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	/**
	 * 用于生成jwt
	 */
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
		accessTokenConverter.setSigningKey("whq");
		return accessTokenConverter;
	}

	/**
	 * 用于扩展jwt
	 */
	@Bean
	@ConditionalOnMissingBean(name = "jwtTokenEnhancer")
	public TokenEnhancer jwtTokenEnhancer(JwtAccessTokenConverter jwtAccessTokenConverter) {
		return new JwtTokenEnhancer(jwtAccessTokenConverter);
	}

}
