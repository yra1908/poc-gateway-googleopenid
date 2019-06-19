package sample;

import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

public class HasAuthorizationHeaderMatcher implements ServerWebExchangeMatcher {
    @Override
    public Mono<MatchResult> matches(ServerWebExchange serverWebExchange) {
        String authorization = serverWebExchange.getRequest()
            .getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return MatchResult.notMatch();
        }
        Map<String, Object> variables = new HashMap();
        variables.put("header", authorization);
        return MatchResult.match(variables);
    }
}
