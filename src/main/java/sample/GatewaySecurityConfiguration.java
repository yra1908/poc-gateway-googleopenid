package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.web.server.WebFilter;
import org.thymeleaf.util.StringUtils;

import java.util.Arrays;

@Configuration
public class GatewaySecurityConfiguration {

    @Value("${provider.clientId}")
    private String clientId;

    @Value("${provider.clientSecret}")
    private String clientSecret;

    @Value("${provider.accessTokenUri}")
    private String accessTokenUri;

    @Value("${provider.userAuthorizationUri}")
    private String userAuthorizationUri;

    @Value("${provider.scope}")
    private String scope;

    @Value("${provider.jwkUrl}")
    private String jwkUrl;

    @Value("${client.registrationId}")
    private String registrationId;

    @Value("${client.redirectUriTemplate}")
    private String redirectUriTemplate;

    @Value("${client.redirectUri}")
    private String redirectUri;

    @Value("${client.authorizationUri}")
    private String authorizationUri;

    @Autowired
    private JWTServiceGoogle jwtService;

    @Bean
    public ClientRegistration clientRegistration() {
        return ClientRegistration
            .withRegistrationId(registrationId)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
            .redirectUriTemplate(redirectUriTemplate)
            .scope(StringUtils.split(scope, ","))
            .authorizationUri(userAuthorizationUri)
            .tokenUri(accessTokenUri)
            .jwkSetUri(jwkUrl)
            .build();
    }

    //need this statefull shit for spring autoconfiguration (we have no state now but it fauls without it)
    @Bean
    public ReactiveClientRegistrationRepository registrationRepository() {
        InMemoryReactiveClientRegistrationRepository clientRegistrationsRepo =
            new InMemoryReactiveClientRegistrationRepository(clientRegistration());
        return clientRegistrationsRepo;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
                .pathMatchers("/ping").permitAll()
                .matchers(new NegatedServerWebExchangeMatcher(new HasAuthorizationCookieMatcher())).denyAll()
                .anyExchange().authenticated()
            .and()
            .addFilterAt(oauthRedirectWebFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
            .addFilterAt(tokenAuthenticationWebFilter(), SecurityWebFiltersOrder.FORM_LOGIN)
            .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
            .exceptionHandling()
                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint(authorizationUri))
            .and()
            .build();
    }

    private WebFilter oauthRedirectWebFilter(){
        OAuthRedirectWebFilter oauthRedirectWebFilter = new OAuthRedirectWebFilter(clientRegistration());
        return oauthRedirectWebFilter;
    }

    private AuthenticationWebFilter authenticationWebFilter(){
        OauthAuthenticationWebFilter oauthAuthenticationWebFilter = new OauthAuthenticationWebFilter(authenticationManager());
        oauthAuthenticationWebFilter.setAuthenticationMatcher(redirectUri);
        oauthAuthenticationWebFilter.setServerAuthenticationConverter(new StatelessServerAuthenticationConverter(clientRegistration()));
        return oauthAuthenticationWebFilter;
    }

    private Oauth2LoginFromTokenWebFilter tokenAuthenticationWebFilter() {
        return new Oauth2LoginFromTokenWebFilter(authenticationManager(), jwtService, clientRegistration());
    }

    private ReactiveAuthenticationManager authenticationManager(){
        return new OidcAuthorizationCodeReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new OidcReactiveOAuth2UserService()
        );
    }

}
