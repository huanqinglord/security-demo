# spring OAuth2 登录接口入口  
@RequestMapping(value = "/oauth/token", method=RequestMethod.POST)  
org.springframework.security.oauth2.provider.endpoint.postAccessToken(Principal principal, @RequestParam Map<String, String> parameters)