package sample;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CustomOauthRequestResolver implements ServerOAuth2AuthorizationRequestResolver {
    public static final String DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    public static final String DEFAULT_AUTHORIZATION_REQUEST_PATTERN = "/oauth2/authorization/{registrationId}";
    private final StringKeyGenerator stateGenerator= new Base64StringKeyGenerator(Base64.getUrlEncoder());;
    private final ServerWebExchangeMatcher authorizationRequestMatcher =  new PathPatternParserServerWebExchangeMatcher(DEFAULT_AUTHORIZATION_REQUEST_PATTERN);
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    public CustomOauthRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
        return this.authorizationRequestMatcher.matches(exchange).filter((matchResult) -> {
            return matchResult.isMatch();
        }).map(ServerWebExchangeMatcher.MatchResult::getVariables).map((variables) -> {
            return variables.get("registrationId");
        }).cast(String.class).flatMap((clientRegistrationId) -> {
            return this.resolve(exchange, clientRegistrationId);
        });
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
        return this.findByRegistrationId(exchange, clientRegistrationId).map((clientRegistration) -> {
            return this.authorizationRequest(exchange, clientRegistration);
        });
    }

    private Mono<ClientRegistration> findByRegistrationId(ServerWebExchange exchange, String clientRegistration) {
        return this.clientRegistrationRepository.findByRegistrationId(clientRegistration).switchIfEmpty(Mono.error(() -> {
            return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client registration id");
        }));
    }

    private OAuth2AuthorizationRequest authorizationRequest(ServerWebExchange exchange, ClientRegistration clientRegistration) {
        String redirectUriStr = this.expandRedirectUri(exchange.getRequest(), clientRegistration);
        Map<String, Object> additionalParameters = new HashMap();
        additionalParameters.put("registration_id", clientRegistration.getRegistrationId());
        OAuth2AuthorizationRequest.Builder builder;
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
            builder = OAuth2AuthorizationRequest.authorizationCode();
        } else {
            if (!AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
                throw new IllegalArgumentException("Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue() + ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
            }

            builder = OAuth2AuthorizationRequest.implicit();
        }

        return builder.clientId(clientRegistration.getClientId()).authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri()).redirectUri(redirectUriStr).scopes(clientRegistration.getScopes()).state(this.stateGenerator.generateKey()).additionalParameters(additionalParameters).build();
    }

    private String expandRedirectUri(ServerHttpRequest request, ClientRegistration clientRegistration) {
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
}
