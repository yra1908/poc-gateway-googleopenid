package sample;

import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

public class HasAuthorizationMatcher implements ServerWebExchangeMatcher {
    private static final String BEARER_TOKEN_PREFIX = "Bearer ";

    @Override
    public Mono<MatchResult> matches(ServerWebExchange exchange) {
        String idToken = null;
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith(BEARER_TOKEN_PREFIX)) {
            idToken = authorization.substring(BEARER_TOKEN_PREFIX.length());
        } else {
            HttpCookie cooKie = exchange.getRequest().getCookies().getFirst("x-auth-token");
            idToken = cooKie != null ? cooKie.getValue() : null;
        }
        if (idToken == null){
            return MatchResult.notMatch();
        }
        Map<String, Object> variables = new HashMap();
        variables.put("x-auth-token", idToken);
        return MatchResult.match(variables);
    }
}
