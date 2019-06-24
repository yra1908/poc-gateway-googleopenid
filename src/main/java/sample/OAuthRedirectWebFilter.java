package sample;

import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;

public class OAuthRedirectWebFilter implements WebFilter {
    private final ServerRedirectStrategy authorizationRedirectStrategy = new DefaultServerRedirectStrategy();
    private final ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;

    public OAuthRedirectWebFilter(ClientRegistration clientRegistration) {
        this.authorizationRequestResolver = new StatelessOauthRequestResolver(clientRegistration);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return this.authorizationRequestResolver.resolve(exchange).switchIfEmpty(chain.filter(exchange).then(Mono.empty())).onErrorResume(ClientAuthorizationRequiredException.class, (e) -> {
            return this.authorizationRequestResolver.resolve(exchange, e.getClientRegistrationId());
        }).flatMap((clientRegistration) -> {
            return this.sendRedirectForAuthorization(exchange, clientRegistration);
        });
    }

    private Mono<Void> sendRedirectForAuthorization(ServerWebExchange exchange, OAuth2AuthorizationRequest authorizationRequest) {
        return Mono.defer(() -> {
            Mono<Void> saveAuthorizationRequest = Mono.empty();
            if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
                return Mono.error(new IllegalArgumentException("wrong authorization_code"));
            }

            URI redirectUri = UriComponentsBuilder.fromUriString(authorizationRequest.getAuthorizationRequestUri()).build(true).toUri();
            return saveAuthorizationRequest.then(this.authorizationRedirectStrategy.sendRedirect(exchange, redirectUri));
        });
    }
}
