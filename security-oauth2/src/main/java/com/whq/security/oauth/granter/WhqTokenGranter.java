
package com.whq.security.oauth.granter;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 自定义拓展TokenGranter
 */
public class WhqTokenGranter {

	/**
	 * 自定义tokenGranter
	 */
	public static TokenGranter getTokenGranter(final AuthenticationManager authenticationManager, final AuthorizationServerEndpointsConfigurer endpoints) {
		// 默认tokenGranter集合
		List<TokenGranter> granters = new ArrayList<>(Collections.singletonList(endpoints.getTokenGranter()));
		// 账号密码模式
		granters.add(new PasswordGranter(authenticationManager, endpoints.getTokenServices(), endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory()));
		// 短信验证码模式
		granters.add(new SMSVerificationTokenGranter(authenticationManager, endpoints.getTokenServices(), endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory()));
		// 组合tokenGranter集合
		return new CompositeTokenGranter(granters);
	}

}
