package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
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
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

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

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
//            .authorizeExchange()
//            .anyExchange().authenticated()
//            .and()
           // .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
//            .and()
//            .oauth2Login()
//                .authenticationConverter(buildInAuthenticationConverter())
//                .clientRegistrationRepository(registrationRepository())
//                .authorizedClientService(clientService())
//                .authenticationManager(buildInReactiveAuthenticationManager())

            .addFilterAt(oauthRedirectFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
            .addFilterAt(tokenAuthenticationFilter(), SecurityWebFiltersOrder.FORM_LOGIN)
            .addFilterAt(authenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)

            //no need to do this - it's the same as .authorizeExchange().anyExchange().authenticated()  .exceptionHandling().authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/login-client"))
            .addFilterAt(authorizationFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
            .addFilterAt(exceptionTranslationWebFilter(), SecurityWebFiltersOrder.EXCEPTION_TRANSLATION)

//            .exceptionHandling()
//                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/login-client"))
//            .and()
            .build();
    }

    private AuthorizationWebFilter authorizationFilter(){
        return new AuthorizationWebFilter(AuthenticatedReactiveAuthorizationManager.authenticated());
    }

    private ExceptionTranslationWebFilter exceptionTranslationWebFilter(){
        ExceptionTranslationWebFilter exceptionWebFilter = new ExceptionTranslationWebFilter();
        exceptionWebFilter.setAuthenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/login-client"));
//        exceptionWebFilter.setAccessDeniedHandler();
        return exceptionWebFilter;
    }

    private ReactiveAuthorizationManager authorizationManager(){
        return AuthenticatedReactiveAuthorizationManager.authenticated();
    }

    private OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter(){
        OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter =
            new OAuth2AuthorizationRequestRedirectWebFilter(registrationRepository());
        return oauthRedirectFilter; //OauthDefault
    }


    private AuthenticationWebFilter authenticationFilter(){
        OauthAuthenticationWebFilter oauthAuthenticationFilter = new OauthAuthenticationWebFilter(buildInReactiveAuthenticationManager());
        oauthAuthenticationFilter.setAuthenticationMatcher("/login/oauth2/code/{registrationId}");
        oauthAuthenticationFilter.setAuthorizedClientRepository(clientRepository());
        oauthAuthenticationFilter.setServerAuthenticationConverter(buildInAuthenticationConverter());
        oauthAuthenticationFilter.setAuthenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler());
        oauthAuthenticationFilter.setAuthenticationFailureHandler(new ServerAuthenticationFailureHandler() {
            public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
                return Mono.error(exception);
            }
        });
        oauthAuthenticationFilter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
        return oauthAuthenticationFilter;
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

    private Oauth2LoginFromTokenWebFilter tokenAuthenticationFilter() {
        return new Oauth2LoginFromTokenWebFilter(jwtService, clientRepository());
    }

    @Bean
    public ReactiveClientRegistrationRepository registrationRepository() {
        InMemoryReactiveClientRegistrationRepository clientRegistrationsRepo =
            new InMemoryReactiveClientRegistrationRepository(clientRegistration());
        return clientRegistrationsRepo;
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientService clientService() {
        return new InMemoryReactiveOAuth2AuthorizedClientService(registrationRepository());
    }

    @Bean
    public ServerOAuth2AuthorizedClientRepository clientRepository() {
        return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(clientService());
    }

}
