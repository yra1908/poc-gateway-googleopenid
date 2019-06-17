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

public class AuthenticationFilter extends AuthenticationWebFilter {
    private RestTemplate restTemplate;

    private final ReactiveAuthenticationManager authenticationManager;
    private ServerWebExchangeMatcher requiresAuthenticationMatcher;
    private ServerAuthenticationConverter authenticationConverter;
    private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    private ServerAuthenticationFailureHandler authenticationFailureHandler = new ServerAuthenticationEntryPointFailureHandler(new HttpBasicServerAuthenticationEntryPoint());

    public AuthenticationFilter(ReactiveAuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
    }

    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setLoginEntryPoint(String loginEntryPoint) {
        this.requiresAuthenticationMatcher = new PathPatternParserServerWebExchangeMatcher(loginEntryPoint);
    }

    public void setAuthenticationConverter(ServerAuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
    }

    public void setAuthorizedClientRepository(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
        this.authorizedClientRepository = authorizedClientRepository;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return isNeedAuth(exchange)
            .filter((matchResult) -> {return matchResult.isMatch();  })
            .flatMap((matchResult) -> { return this.convertValidate(exchange);})
            .switchIfEmpty(chain.filter(exchange)
                    .then(Mono.error(new ClientAuthorizationRequiredException("login-client"))))
            .flatMap((token) -> {
                return this.authenticate(exchange, chain, token);
            });
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

        /*WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, chain);
        return this.authenticationManager.authenticate(token).switchIfEmpty(Mono.defer(() -> {
            return Mono.error(new IllegalStateException("No provider found for " + token.getClass()));
        })).flatMap((authentication) -> {
            return this.onAuthenticationSuccess(authentication, webFilterExchange);
        }).onErrorResume(AuthenticationException.class, (e) -> {
            return this.authenticationFailureHandler.onAuthenticationFailure(webFilterExchange, e);
        });*/
    }

    @Override
    protected Mono<Void> onAuthenticationSuccess(Authentication authentication,
                                                 WebFilterExchange webFilterExchange) {
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) authentication;
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(),
                authenticationResult.getName(),
                authenticationResult.getAccessToken(),
                authenticationResult.getRefreshToken());
        OAuth2AuthenticationToken result =  new OAuth2AuthenticationToken(
                authenticationResult.getPrincipal(),
                authenticationResult.getAuthorities(),
                authenticationResult.getClientRegistration().getRegistrationId());
        return this.authorizedClientRepository
                .saveAuthorizedClient(authorizedClient, authenticationResult, webFilterExchange.getExchange())
                .then(super.onAuthenticationSuccess(result, webFilterExchange));
    }

}
