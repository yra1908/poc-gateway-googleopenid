package sample;

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
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@Configuration
public abstract class GatewaySecurityConfiguration {

    @Bean
    public abstract ClientRegistration clientRegistration();

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
            .matchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class)).permitAll()
            .anyExchange().authenticated()
            .and()
            //next line - config for stateless web session
            .addFilterAt(authenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
            .oauth2Login()
            .and()
            .exceptionHandling()
            .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .build();
    }

    @Bean
    public AuthenticationWebFilter authenticationFilter() {
        AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(reactiveAuthenticationManager());
        authenticationFilter.setServerAuthenticationConverter(tokenAuthenticationConverter());
        authenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return authenticationFilter;
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return new OidcAuthorizationCodeReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new OidcReactiveOAuth2UserService()
        );
    }

    protected ServerAuthenticationConverter tokenAuthenticationConverter() {
        return serverWebExchange -> {
            String authorization = serverWebExchange.getRequest()
                .getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || !authorization.startsWith("Bearer "))
                return Mono.empty();
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
