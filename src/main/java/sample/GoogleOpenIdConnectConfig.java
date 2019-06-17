package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@Configuration
public class GoogleOpenIdConnectConfig {

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
    private RestTemplate vanilaRestTemplatye;

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

    @Bean
    public ReactiveClientRegistrationRepository registrationRepository(){
        InMemoryReactiveClientRegistrationRepository clientRegistrationsRepo =
            new InMemoryReactiveClientRegistrationRepository(clientRegistration());
        return clientRegistrationsRepo;
    }

    @Bean
    public OAuth2AuthorizationRequestRedirectWebFilter redirectWebFilter() {
        OAuth2AuthorizationRequestRedirectWebFilter oAuth2AuthorizationRequestRedirectWebFilter =
            new OAuth2AuthorizationRequestRedirectWebFilter(registrationRepository());
        return oAuth2AuthorizationRequestRedirectWebFilter;
    }

    @Bean
    public ServerAuthenticationConverter authenticationConverter() {
        ServerOAuth2AuthorizationCodeAuthenticationTokenConverter authenticationConverter =
            new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(registrationRepository());
        authenticationConverter.setAuthorizationRequestRepository(new WebSessionOAuth2ServerAuthorizationRequestRepository());
        return authenticationConverter;
    }

    @Bean
    public AuthenticationFilter authenticationFilter() {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(reactiveAuthenticationManager());
        authenticationFilter.setAuthenticationConverter(authenticationConverter());
        authenticationFilter.setRestTemplate(vanilaRestTemplatye);
        authenticationFilter.setLoginEntryPoint("/login/oauth2/code/login-client");
        authenticationFilter.setAuthorizedClientRepository(serverOAuth2AuthorizedClientRepository());
        return authenticationFilter;
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(){
        OidcReactiveOAuth2UserService userService = new OidcReactiveOAuth2UserService();
        OidcAuthorizationCodeReactiveAuthenticationManager reactiveAuthenticationManager =
            new OidcAuthorizationCodeReactiveAuthenticationManager(
                new WebClientReactiveAuthorizationCodeTokenResponseClient(),
                userService
            );

        return reactiveAuthenticationManager;

    }

    @Bean
    public ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService(){
        return new InMemoryReactiveOAuth2AuthorizedClientService(registrationRepository());
    }

    @Bean
    public ServerOAuth2AuthorizedClientRepository serverOAuth2AuthorizedClientRepository(){
        return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(oAuth2AuthorizedClientService());
    }

    /*private static class StatelessAuthenticationMaanager implements ReactiveAuthenticationManager {
        @Override
        public Mono<Authentication> authenticate(Authentication authentication) {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }
    }*/
}
