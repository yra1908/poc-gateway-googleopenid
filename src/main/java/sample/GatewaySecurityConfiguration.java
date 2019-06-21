package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.web.server.WebFilter;

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

    @Value("${provider.redirectUri}")
    private String redirectUri;

    @Value("${provider.jwkUrl}")
    private String jwkUrl;

    @Autowired
    private JWTServiceGoogle jwtService;

    @Bean
    public ClientRegistration clientRegistration() {
        return ClientRegistration
            .withRegistrationId("login-client")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
            .redirectUriTemplate(redirectUri)
            .scope(Arrays.asList("openid", "profile"))
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
                .anyExchange().authenticated()
            .and()
            .addFilterAt(oauthRedirectWebFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
            .addFilterAt(tokenAuthenticationWebFilter(), SecurityWebFiltersOrder.FORM_LOGIN)
            .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
            .exceptionHandling()
                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/login-client"))
            .and()
            .build();
    }

    private WebFilter oauthRedirectWebFilter(){
        OAuthRedirectWebFilter oauthRedirectWebFilter = new OAuthRedirectWebFilter(clientRegistration());
        return oauthRedirectWebFilter;
    }

    private AuthenticationWebFilter authenticationWebFilter(){
        OauthAuthenticationWebFilter oauthAuthenticationWebFilter = new OauthAuthenticationWebFilter();
        oauthAuthenticationWebFilter.setAuthenticationMatcher("/login/oauth2/code/{registrationId}");
        oauthAuthenticationWebFilter.setServerAuthenticationConverter(new StatelessServerAuthenticationConverter(clientRegistration()));
        return oauthAuthenticationWebFilter;
    }

    private Oauth2LoginFromTokenWebFilter tokenAuthenticationWebFilter() {
        return new Oauth2LoginFromTokenWebFilter(jwtService, clientRegistration());
    }

}
