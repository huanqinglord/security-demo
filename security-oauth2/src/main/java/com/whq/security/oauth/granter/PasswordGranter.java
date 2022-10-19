package com.whq.security.oauth.granter;

import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

public class PasswordGranter extends AbstractTokenGranter {

	public static final String GRANT_TYPE = "pwd";

	private final AuthenticationManager authenticationManager;

	public PasswordGranter(AuthenticationManager authenticationManager,
                           AuthorizationServerTokenServices tokenServices,
						   ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
		this(authenticationManager, tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
	}

	protected PasswordGranter(AuthenticationManager authenticationManager, AuthorizationServerTokenServices tokenServices,
							  ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
		super(tokenServices, clientDetailsService, requestFactory, grantType);
		this.authenticationManager = authenticationManager;
	}

	@Override
	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		Map<String, String> parameters = new LinkedHashMap(tokenRequest.getRequestParameters());
		String username = parameters.get("username");
		String cryptPassword = parameters.get("password");

		Authentication userAuth = new UsernamePasswordAuthenticationToken(username, cryptPassword);
		((AbstractAuthenticationToken) userAuth).setDetails(parameters);
		try {
			// 以下代码为spring security 授权认证逻辑
			userAuth = authenticationManager.authenticate(userAuth);
		} catch (AccountStatusException | BadCredentialsException ase) {
			throw new InvalidGrantException(ase.getMessage());
		}

		if (userAuth == null || !userAuth.isAuthenticated()) {
			throw new InvalidGrantException("Could not authenticate user: " + username);
		}

		OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
		return new OAuth2Authentication(storedOAuth2Request, userAuth);
	}
}
