package sample;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class OauthAuthenticationWebFilter extends AuthenticationWebFilter {

    public OauthAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
        super(authenticationManager);
        RedirectServerAuthenticationSuccessHandler authenticationSuccessHandler = new RedirectServerAuthenticationSuccessHandler();
        authenticationSuccessHandler.setRedirectStrategy(new CustomRedirectStrategy());
        setAuthenticationSuccessHandler(authenticationSuccessHandler);
        setAuthenticationFailureHandler(new ServerAuthenticationFailureHandler() {
            public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
                return Mono.error(exception);
            }
        });
    }

    public void setAuthenticationMatcher(String pattern) {
        setRequiresAuthenticationMatcher(new PathPatternParserServerWebExchangeMatcher(pattern));
    }

    protected Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken)authentication;
        DefaultOidcUser principal = (DefaultOidcUser) authenticationResult.getPrincipal();
        String tokenValue = principal.getIdToken().getTokenValue();
        //TODO:YC to think about another way to transfering idToken to To CustomRedirectStrategy
        exchange.getResponse().getHeaders().add("x-auth-token", tokenValue);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(authenticationResult.getClientRegistration(), authenticationResult.getName(), authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
        OAuth2AuthenticationToken result = new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities(), authenticationResult.getClientRegistration().getRegistrationId());
        return super.onAuthenticationSuccess(result, webFilterExchange);
    }

    private Mono<Void> onAuthenticationFailure() {
        return Mono.error(new OAuth2AuthenticationException(new OAuth2Error("401")));
    }

}
