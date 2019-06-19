package sample;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import java.util.Arrays;
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

    @Bean
//    public abstract ClientRegistration clientRegistration();//
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
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
//            .matchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class)).permitAll()
            .anyExchange().authenticated()
            .and()
            //next line - config for stateless web session
            .addFilterAt(authenticationFilter(), SecurityWebFiltersOrder.OAUTH2_AUTHORIZATION_CODE)
            .oauth2Login().authenticationConverter(tokenAuthenticationConverter())
            .and()
            .exceptionHandling()
            .and()
//            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .build();
    }

    @Bean
    public AuthenticationWebFilter authenticationFilter() {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(
                buildInReactiveAuthenticationManager(),
                new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
                        new InMemoryReactiveOAuth2AuthorizedClientService(registrationRepository())
                ));
        authenticationFilter.setAuthenticationConverter(tokenAuthenticationConverter());
        authenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        authenticationFilter.setLoginEntryPoint("/login/oauth2/code/login-client");
        return authenticationFilter;
    }

    @Bean
    public ReactiveAuthenticationManager buildInReactiveAuthenticationManager() {
        return new OidcAuthorizationCodeReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new OidcReactiveOAuth2UserService()
        );
    }

    /*@Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
//        return new OidcAuthorizationCodeReactiveAuthenticationManager(
//            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
//            new OidcReactiveOAuth2UserService()
//        );
        return authentication -> {
            OpenIdConnectUserDetails user = null;
            String idToken = (String) authentication.getCredentials();
            try {
                JWTClaimsSet claims = null;
                String kid = JwtHelper.headers(idToken).get("kid");
                Jwt tokenDecoded = JwtHelper.decodeAndVerify(idToken, verifier(kid));
                Map<String, Object> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
                verifyClaims(authInfo);
                user =  new OpenIdConnectUserDetails(authInfo, authentication.getCredentials());
            } catch (Exception e) {
                e.printStackTrace();
            }

            Mono<OpenIdConnectUserDetails> userDtoMono = user == null ?
                    fetchUserDto() : Mono.just(user);

            return userDtoMono
//                .doOnNext(PrincipalImpl::eraseCredentials)
                    .map(principal -> new OAuth2AuthenticationToken(
                            new DefaultOAuth2User(principal.getAuthorities(), principal.getUserInfo(), "sub"),
                            principal.getAuthorities(),
                            "login-client"));
        };
    }*/

    @Bean
    public ServerAuthenticationConverter buildInAuthenticationConverter() {
        ServerOAuth2AuthorizationCodeAuthenticationTokenConverter authenticationConverter =
                new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(registrationRepository());
        authenticationConverter.setAuthorizationRequestRepository(new CustomWebSessionOAuth2ServerAuthorizationRequestRepository());
        return authenticationConverter;
    }

    protected ServerAuthenticationConverter tokenAuthenticationConverter() {
        return serverWebExchange -> {
            String authorization = serverWebExchange.getRequest()
                .getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || !authorization.startsWith("Bearer ")){
                return buildInAuthenticationConverter().convert(serverWebExchange);
            }
            return Mono.just(new UsernamePasswordAuthenticationToken(null, authorization.substring("Bearer ".length())));
        };
    }

    protected ServerAuthenticationFailureHandler authenticationFailureHandler() {
        return (webFilterExchange, exception) -> Mono.error(exception);
    }

    protected ServerAccessDeniedHandler accessDeniedHandler() {
        return (exchange, exception) -> Mono.error(exception);
    }
}
