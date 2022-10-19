
package com.whq.security.oauth.factory;


import com.whq.security.oauth.user.MyUser;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.HashMap;
import java.util.Map;

@AllArgsConstructor
public class JwtTokenEnhancer implements TokenEnhancer {

	private final JwtAccessTokenConverter jwtAccessTokenConverter;

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		MyUser principal = (MyUser) authentication.getUserAuthentication().getPrincipal();

		// token参数增强
		// todo 以下可根据自身业务自由设置，方便于解析token后获取到有价值的信息
		Map<String, Object> info = new HashMap<>(16);
		info.put("user_id", principal.getUserId());
		info.put("user_name", principal.getUsername());
		info.put("user_phone", "18788888888");
		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);

		OAuth2AccessToken oAuth2AccessToken = jwtAccessTokenConverter.enhance(accessToken, authentication);
		String tokenValue = oAuth2AccessToken.getValue();
		String tenantId = principal.getTenantId();
		String userId = principal.getUserId() == null ? "" : principal.getUserId().toString();
		// todo 此处可以将token存入redis
		// RedisTokenUtil.addAccessToken();

		return accessToken;
	}
}
