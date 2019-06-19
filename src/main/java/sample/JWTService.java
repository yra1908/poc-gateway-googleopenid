package sample;

import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

public interface JWTService {
    Mono<Authentication> retrieveAuthenticationFromToken(String idToken);
}
