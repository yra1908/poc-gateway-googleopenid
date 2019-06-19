package sample;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class AuthenticationFilter extends OAuth2LoginAuthenticationWebFilter {
    private final ReactiveAuthenticationManager authenticationManager;
    private ServerWebExchangeMatcher requiresAuthenticationMatcher;
    private ServerAuthenticationConverter authenticationConverter;
    private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    private ServerAuthenticationFailureHandler authenticationFailureHandler = new ServerAuthenticationEntryPointFailureHandler(new HttpBasicServerAuthenticationEntryPoint());

    public AuthenticationFilter(ReactiveAuthenticationManager authenticationManager, ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
        super(authenticationManager, authorizedClientRepository);
        this.authenticationManager = authenticationManager;
        this.authorizedClientRepository = authorizedClientRepository;
    }

    public void setLoginEntryPoint(String loginEntryPoint) {
        this.requiresAuthenticationMatcher = new PathPatternParserServerWebExchangeMatcher(loginEntryPoint);
    }

    public void setAuthenticationConverter(ServerAuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return this.requiresAuthenticationMatcher.matches(exchange)
                .filter( matchResult -> matchResult.isMatch())
                .flatMap( matchResult -> this.authenticationConverter.convert(exchange))
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .flatMap( token -> authenticate(exchange, chain, token));
    }

    private void throwException() {
        Mono.just(new ClientAuthorizationRequiredException("login-client"));
    }

    private Mono<ServerWebExchangeMatcher.MatchResult> isNeedAuth(ServerWebExchange exchange){
        return this.requiresAuthenticationMatcher.matches(exchange);
    }

    private Mono<Authentication> convertValidate(ServerWebExchange exchange){
        return this.authenticationConverter.convert(exchange);
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain, Authentication token) {

        System.out.println("**********************");
        System.out.println("authentication party");
        System.out.println("*********************");

        WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);
        return this.authenticationManager.authenticate(token).switchIfEmpty(Mono.defer(() -> {
            return Mono.error(new IllegalStateException("No provider found for " + token.getClass()));
        })).flatMap((authentication) -> {
            return this.onAuthenticationSuccess(authentication, webFilterExchange);
        }).onErrorResume(AuthenticationException.class, (e) -> {
            return authenticationFailureHandler.onAuthenticationFailure(webFilterExchange, e);
        });

    }

}
