package sample;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Component
public class JWTService {

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

    @Value("${provider.issuer}")
    private String issuer;

    @Value("${provider.jwkUrl}")
    private String jwkUrl;



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

    public Mono<Authentication> parseToken (String idToken){
        try {
            String kid = JwtHelper.headers(idToken).get("kid");
            Jwt tokenDecoded = JwtHelper.decodeAndVerify(idToken, verifier(kid));
            Map<String, Object> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
            Instant at = Instant.ofEpochSecond((Integer) authInfo.get("iat"));
            Instant exp = Instant.ofEpochSecond((Integer) authInfo.get("exp"));
            verifyClaims(authInfo);
            OidcIdToken token = new OidcIdToken(idToken, at, exp, authInfo);
            OAuth2User user =  new DefaultOidcUser(Collections.singletonList(new OidcUserAuthority(token)), token);
            Set<String> scopes = new HashSet<>(Arrays.asList("openid", "profile", "email"));
            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, idToken,at, exp,  scopes);
            OAuth2AuthorizationExchange exchangeStub = new OAuth2AuthorizationExchange(
                OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(userAuthorizationUri)
                    .clientId(clientId)
                    .redirectUri(redirectUri)
                    .scope("openid", "email", "profile")
                    .state("random")
                    .build(),
                OAuth2AuthorizationResponse.success("200")
                    .redirectUri(redirectUri)
                    .state("random")
                    .build());
            return Mono.just(new OAuth2LoginAuthenticationToken(clientRegistration(), exchangeStub, user, user.getAuthorities(), accessToken, null));
//            return new OAuth2AuthorizationCodeAuthenticationToken(clientRegistration(), exchangeStub, accessToken);
        } catch (Exception e) {
            e.printStackTrace();
            return Mono.empty();
        }
    }

    public void verifyClaims(Map claims) {
        int exp = (int) claims.get("exp");
        Date expireDate = new Date(exp * 1000L);
        Date now = new Date();
        if (expireDate.before(now) || !claims.get("iss").equals(issuer) || !claims.get("aud").equals(clientId)) {
            throw new RuntimeException("Invalid claims");
        }
    }

    private RsaVerifier verifier(String kid) throws Exception {
        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        Jwk jwk = provider.get(kid);
        return new RsaVerifier((RSAPublicKey) jwk.getPublicKey());
    }
}
