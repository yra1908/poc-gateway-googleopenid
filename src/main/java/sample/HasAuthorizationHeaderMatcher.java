package sample;

import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HasAuthorizationHeaderMatcher implements ServerWebExchangeMatcher {
    @Override
    public Mono<MatchResult> matches(ServerWebExchange exchange) {
        return exchange.getRequest().getCookies()
            .getOrDefault("x-auth-token", Collections.emptyList())
            .stream()
            .map(cookie -> {
                Map<String, Object> variables = new HashMap();
                variables.put("x-auth-token", cookie.getValue());
                return MatchResult.match(variables);
            })
            .findFirst()
            .orElse(MatchResult.notMatch());
    }

    /*public Mono<MatchResult> matches(ServerWebExchange exchange) {
        String cookie = exchange.getRequest().getHeaders()
            .getOrDefault(HttpHeaders.COOKIE, Collections.emptyList()).stream()
            .filter(coockie -> {
                return StringUtils.startsWithIgnoreCase(coockie, "session");
            })
            .findFirst()
            .orElse(null);
        if (cookie == null) {
            return MatchResult.notMatch();
        }
        Map<String, Object> variables = new HashMap();
        variables.put("token", cookie);
        return MatchResult.match(variables);
    }*/

    /*public Mono<MatchResult> matches(ServerWebExchange serverWebExchange) {
        String authorization = serverWebExchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return MatchResult.notMatch();
        }
        Map<String, Object> variables = new HashMap();
        variables.put("header", authorization);
        return MatchResult.match(variables);
    }*/
}
