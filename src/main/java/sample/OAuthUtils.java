package sample;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

public class OAuthUtils {
    public static final String BEARER_TOKEN_PREFIX = "Bearer ";

    public static String expandRedirectUri(ServerHttpRequest request, ClientRegistration clientRegistration) {
        Map<String, String> uriVariables = new HashMap();
        uriVariables.put("registrationId", clientRegistration.getRegistrationId());
        String baseUrl = UriComponentsBuilder.fromHttpRequest(new ServerHttpRequestDecorator(request)).replacePath(request.getPath().contextPath().value()).replaceQuery((String)null).build().toUriString();
        uriVariables.put("baseUrl", baseUrl);
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
            String loginAction = "login";
            uriVariables.put("action", loginAction);
        }
        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate()).buildAndExpand(uriVariables).toUriString();
    }

    public static void addAuthorizationHeaderToResponse(Authentication authentication, ServerWebExchange exchange) {
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken)authentication;
        DefaultOidcUser principal = (DefaultOidcUser) authenticationResult.getPrincipal();
        String idToken = principal.getIdToken().getTokenValue();
        exchange.getResponse().getHeaders().setBearerAuth(idToken);
    }
}
