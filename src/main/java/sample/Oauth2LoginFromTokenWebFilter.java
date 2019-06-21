package sample;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class Oauth2LoginFromTokenWebFilter extends AuthenticationWebFilter {
    private ServerWebExchangeMatcher requiresAuthenticationMatcher = new HasAuthorizationHeaderMatcher();
    private JWTServiceGoogle jwtService;
    private ClientRegistration clientRegistration;

    public Oauth2LoginFromTokenWebFilter(ReactiveAuthenticationManager authenticationManager, JWTServiceGoogle jwtService) {
        super(authenticationManager);
        this.jwtService = jwtService;
    }

    public Oauth2LoginFromTokenWebFilter(JWTServiceGoogle jwtService, ClientRegistration clientRegistration) {
        this(getAuthManagerStub(), jwtService);
        this.clientRegistration = clientRegistration;
    }

    private static ReactiveAuthenticationManager getAuthManagerStub() {
        return new OidcAuthorizationCodeReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new OidcReactiveOAuth2UserService()
        );
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return this.requiresAuthenticationMatcher.matches(exchange)
            .filter((matchResult) -> {
                return matchResult.isMatch();
            })
            .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
            .flatMap((bearerToken) -> {
                return this.authenticate(exchange, chain);
            });
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain) {
        WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String idToken = authorization.substring("Bearer ".length());
        exchange.getResponse().getHeaders().add("x-auth-token", idToken);
        return this.jwtService.retrieveAuthenticationFromToken(idToken)
            .switchIfEmpty(Mono.defer(() -> {
                return Mono.error(new IllegalStateException("Error extracting Authentication from token. Token Not valid"));
            }))
            .flatMap((authentication) -> {
                return this.onAuthenticationSuccess(authentication, webFilterExchange);
            })
            .onErrorResume(AuthenticationException.class, (e) -> {
                return this.onAuthenticationFailure();
            });
    }

    private Mono<Void> onAuthenticationFailure() {
        return Mono.error(new OAuth2AuthenticationException(new OAuth2Error("401")));
    }

    @Override
    protected Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) authentication;
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(authenticationResult.getClientRegistration(), authenticationResult.getName(), authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
        OAuth2AuthenticationToken result = new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities(), authenticationResult.getClientRegistration().getRegistrationId());
        return super.onAuthenticationSuccess(result, webFilterExchange);
    }
}
