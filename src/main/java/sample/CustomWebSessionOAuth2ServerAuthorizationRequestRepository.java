package sample;

import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

public class CustomWebSessionOAuth2ServerAuthorizationRequestRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = WebSessionOAuth2ServerAuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST";
    private final String sessionAttributeName;

    public CustomWebSessionOAuth2ServerAuthorizationRequestRepository() {
        this.sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;
    }

    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
        String state = this.getStateParameter(exchange);
        return state == null ? Mono.empty() : this.getStateToAuthorizationRequest(exchange).filter((stateToAuthorizationRequest) -> {
            return stateToAuthorizationRequest.containsKey(state);
        }).map((stateToAuthorizationRequest) -> {
            return (OAuth2AuthorizationRequest)stateToAuthorizationRequest.get(state);
        });
    }

    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
        Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
        return this.saveStateToAuthorizationRequest(exchange).doOnNext((stateToAuthorizationRequest) -> {
            OAuth2AuthorizationRequest var10000 = (OAuth2AuthorizationRequest)stateToAuthorizationRequest.put(authorizationRequest.getState(), authorizationRequest);
        }).then();
    }

    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
        String state = this.getStateParameter(exchange);
        return state == null ? Mono.empty() : exchange.getSession().map(WebSession::getAttributes).handle((sessionAttrs, sink) -> {
            Map<String, OAuth2AuthorizationRequest> stateToAuthzRequest = this.sessionAttrsMapStateToAuthorizationRequest(sessionAttrs);
            OAuth2AuthorizationRequest removedValue = (OAuth2AuthorizationRequest)stateToAuthzRequest.get(state);
            sink.next(removedValue);

        });
    }

    private String getStateParameter(ServerWebExchange exchange) {
        Assert.notNull(exchange, "exchange cannot be null");
        return (String)exchange.getRequest().getQueryParams().getFirst("state");
    }

    private Mono<Map<String, Object>> getSessionAttributes(ServerWebExchange exchange) {
        return exchange.getSession().map(WebSession::getAttributes);
    }

    private Mono<Map<String, OAuth2AuthorizationRequest>> getStateToAuthorizationRequest(ServerWebExchange exchange) {
        Assert.notNull(exchange, "exchange cannot be null");
        return this.getSessionAttributes(exchange).flatMap((sessionAttrs) -> {
            return Mono.justOrEmpty(this.sessionAttrsMapStateToAuthorizationRequest(sessionAttrs));
        });
    }

    private Mono<Map<String, OAuth2AuthorizationRequest>> saveStateToAuthorizationRequest(ServerWebExchange exchange) {
        Assert.notNull(exchange, "exchange cannot be null");
        return this.getSessionAttributes(exchange).doOnNext((sessionAttrs) -> {
            Object stateToAuthzRequest = sessionAttrs.get(this.sessionAttributeName);
            if (stateToAuthzRequest == null) {
                stateToAuthzRequest = new HashMap();
            }

            sessionAttrs.put(this.sessionAttributeName, stateToAuthzRequest);
        }).flatMap((sessionAttrs) -> {
            return Mono.justOrEmpty(this.sessionAttrsMapStateToAuthorizationRequest(sessionAttrs));
        });
    }

    private Map<String, OAuth2AuthorizationRequest> sessionAttrsMapStateToAuthorizationRequest(Map<String, Object> sessionAttrs) {
        return (Map)sessionAttrs.get(this.sessionAttributeName);
    }
}
