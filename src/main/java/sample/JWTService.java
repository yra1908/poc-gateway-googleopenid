package sample;

import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class JWTService {

    public OAuth2LoginAuthenticationToken parseToken (String idToken){


        return null;
//        return new OAuth2LoginAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange(), oauth2User, mappedAuthorities, accessToken, accessTokenResponse.getRefreshToken());
    }
}
