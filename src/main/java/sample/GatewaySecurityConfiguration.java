package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import reactor.core.publisher.Mono;

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

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
            .anyExchange().authenticated()
            .and()
            .oauth2Login()
                .authenticationConverter(buildInAuthenticationConverter())
                .clientRegistrationRepository(registrationRepository())
                .authorizedClientService(clientService())
                .authenticationManager(buildInReactiveAuthenticationManager())
            .and()
            .addFilterAt(tokenAuthFilter(), SecurityWebFiltersOrder.FORM_LOGIN)
            .exceptionHandling()
            .and()
            .build();
    }

    private Oauth2LoginFromTokenWebFilter tokenAuthFilter(){
        return new Oauth2LoginFromTokenWebFilter(jwtService, clientRepository());
    }

    public ReactiveAuthenticationManager buildInReactiveAuthenticationManager() {
        return new OidcAuthorizationCodeReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new OidcReactiveOAuth2UserService()
        );
    }

    private ServerAuthenticationConverter buildInAuthenticationConverter() {
        ServerOAuth2AuthorizationCodeAuthenticationTokenConverter authenticationConverter =
            new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(registrationRepository());
        authenticationConverter.setAuthorizationRequestRepository(new WebSessionOAuth2ServerAuthorizationRequestRepository());
        return authenticationConverter;
    }

    @Bean
    public ReactiveClientRegistrationRepository registrationRepository() {
        InMemoryReactiveClientRegistrationRepository clientRegistrationsRepo =
            new InMemoryReactiveClientRegistrationRepository(clientRegistration());
        return clientRegistrationsRepo;
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientService clientService(){
        return new InMemoryReactiveOAuth2AuthorizedClientService(registrationRepository());
    }

    @Bean
    public ServerOAuth2AuthorizedClientRepository clientRepository(){
        return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(clientService());
    }

}
