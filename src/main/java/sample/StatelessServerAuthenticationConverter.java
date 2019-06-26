package sample;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

public class StatelessServerAuthenticationConverter implements ServerAuthenticationConverter {
    private final ClientRegistration clientRegistration;

    public StatelessServerAuthenticationConverter(ClientRegistration clientRegistration) {
        this.clientRegistration = clientRegistration;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        OAuth2AuthorizationRequest authorizationRequest = buildAuthorizationRequest(exchange, clientRegistration);
        return Mono.just(authorizationRequest).map((client) -> {
            OAuth2AuthorizationResponse authorizationResponse = convertResponse(exchange);
            OAuth2AuthorizationCodeAuthenticationToken authenticationRequest =
                new OAuth2AuthorizationCodeAuthenticationToken(
                    clientRegistration,
                    new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
            return authenticationRequest;
        });
    }

    private OAuth2AuthorizationRequest buildAuthorizationRequest(ServerWebExchange exchange, ClientRegistration clientRegistration) {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put("registrationId", clientRegistration.getRegistrationId());
        return OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
            .clientId(clientRegistration.getClientId())
            .redirectUri(OAuthUtils.expandRedirectUri(exchange.getRequest(), clientRegistration))
            .scopes(clientRegistration.getScopes())
            .state(getStateParameter(exchange))
            .additionalParameters(additionalParams)
            .build();
    }

    private String getStateParameter(ServerWebExchange exchange) {
        return exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
    }

    private <T> Mono<T> oauth2AuthorizationException(String errorCode) {
        return Mono.defer(() -> {
            OAuth2Error oauth2Error = new OAuth2Error(errorCode);
            return Mono.error(new OAuth2AuthorizationException(oauth2Error));
        });
    }

    private static OAuth2AuthorizationResponse convertResponse(ServerWebExchange exchange) {
        MultiValueMap<String, String> queryParams = exchange.getRequest().getQueryParams();
        String redirectUri = UriComponentsBuilder.fromUri(exchange.getRequest().getURI())
            .query((String)null)
            .build()
            .toUriString();
        return convert(queryParams, redirectUri);
    }

    private static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
        String code = (String)request.getFirst("code");
        String errorCode = (String)request.getFirst("error");
        String state = (String)request.getFirst("state");
        if (StringUtils.hasText(code)) {
            return OAuth2AuthorizationResponse.success(code)
                .redirectUri(redirectUri)
                .state(state)
                .build();
        } else {
            String errorDescription = (String)request.getFirst("error_description");
            String errorUri = (String)request.getFirst("error_uri");
            return OAuth2AuthorizationResponse.error(errorCode)
                .redirectUri(redirectUri)
                .errorDescription(errorDescription)
                .errorUri(errorUri)
                .state(state).build();
        }
    }
}
