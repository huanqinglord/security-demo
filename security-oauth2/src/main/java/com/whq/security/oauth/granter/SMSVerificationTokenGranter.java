package com.whq.security.oauth.granter;


import com.whq.security.oauth.token.SMSVerificationAuthenticationToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

public class SMSVerificationTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "SMSVerification";

    private final AuthenticationManager authenticationManager;

    public SMSVerificationTokenGranter(AuthenticationManager authenticationManager,
                                       AuthorizationServerTokenServices tokenServices,
                                       ClientDetailsService clientDetailsService,
                                       OAuth2RequestFactory requestFactory) {
        this(authenticationManager, tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    }

    protected SMSVerificationTokenGranter(AuthenticationManager authenticationManager,
                                          AuthorizationServerTokenServices tokenServices,
                                          ClientDetailsService clientDetailsService,
                                          OAuth2RequestFactory requestFactory,
                                          String grantType) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap(tokenRequest.getRequestParameters());
        String smsCode = parameters.get("SMS-Code");
        String phone = parameters.get("phone");
        parameters.remove("SMS-Code");

        Authentication userAuth = new SMSVerificationAuthenticationToken(phone, smsCode);
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);
        try {
            // 以下代码为spring security 授权认证逻辑
            userAuth = authenticationManager.authenticate(userAuth);
        } catch (AccountStatusException | BadCredentialsException ase) {
            throw new InvalidGrantException(ase.getMessage());
        }
        if (userAuth == null || !userAuth.isAuthenticated()) {
            throw new InvalidGrantException("Could not authenticate user: " + phone);
        }

        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }
}