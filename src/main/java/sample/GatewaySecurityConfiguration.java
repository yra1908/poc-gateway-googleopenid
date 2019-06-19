package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
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
    private JWTService jwtService;

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
            .oauth2Login()
            .authenticationConverter(tokenAuthenticationConverter())
            .clientRegistrationRepository(registrationRepository())
            .authorizedClientService(buildInAuthorizedClientService())
            .authenticationManager(buildInReactiveAuthenticationManager())
            .and()
            .exceptionHandling()
            .and()
            .build();
    }

//    @Bean
    public ReactiveOAuth2AuthorizedClientService buildInAuthorizedClientService() {
        return new InMemoryReactiveOAuth2AuthorizedClientService(
            new InMemoryReactiveClientRegistrationRepository(clientRegistration()));
    }


//    @Bean
    public ReactiveAuthenticationManager buildInReactiveAuthenticationManager() {
        return new OidcAuthorizationCodeReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new OidcReactiveOAuth2UserService()
        );
    }

    /*@Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return authentication -> {



            return userDtoMono
//                .doOnNext(PrincipalImpl::eraseCredentials)
                    .map(principal -> new OAuth2AuthenticationToken(
                            new DefaultOAuth2User(principal.getAuthorities(), principal.getUserInfo(), "sub"),
                            principal.getAuthorities(),
                            "login-client"));
        };
    }*/


    private ServerAuthenticationConverter tokenAuthenticationConverter() {
        return serverWebExchange -> {
            String authorization = serverWebExchange.getRequest()
                .getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                return buildInAuthenticationConverter().convert(serverWebExchange);
            }
            OAuth2LoginAuthenticationToken authentication = jwtService.parseToken(authorization.substring("Bearer ".length()));
            return Mono.just(authentication);
        };
    }

    private ServerAuthenticationConverter buildInAuthenticationConverter() {
        ServerOAuth2AuthorizationCodeAuthenticationTokenConverter authenticationConverter =
            new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(registrationRepository());
        authenticationConverter.setAuthorizationRequestRepository(new CustomWebSessionOAuth2ServerAuthorizationRequestRepository());
        return authenticationConverter;
    }

}
