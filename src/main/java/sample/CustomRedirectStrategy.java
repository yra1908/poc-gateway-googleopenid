package sample;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

public class CustomRedirectStrategy implements ServerRedirectStrategy {
    private HttpStatus httpStatus;
    private boolean contextRelative;

    public CustomRedirectStrategy() {
        this.httpStatus = HttpStatus.FOUND;
        this.contextRelative = true;
    }

    @Override
    public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(this.httpStatus);
            response.getHeaders().setLocation(createLocation(exchange, location));
            String token = exchange.getResponse().getHeaders().getFirst("x-auth-token");
            response.getHeaders().remove("x-auth-token");
            response.getHeaders().add("blabla", "blaBlaBla");
            if (!StringUtils.isEmpty(token)) {
                ResponseCookie tokenCookie = ResponseCookie
                    .from("x-auth-token", token)
                    .path("/")
                    .httpOnly(true)
                    .build();
                response.getCookies().add("x-auth-token", tokenCookie);
            }
        });
    }

    private URI createLocation(ServerWebExchange exchange, URI location) {
        if (!this.contextRelative) {
            return location;
        } else {
            String url = location.toASCIIString();
            if (url.startsWith("/")) {
                String context = exchange.getRequest().getPath().contextPath().value();
                return URI.create(context + url);
            } else {
                return location;
            }
        }
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        Assert.notNull(httpStatus, "httpStatus cannot be null");
        this.httpStatus = httpStatus;
    }

    public void setContextRelative(boolean contextRelative) {
        this.contextRelative = contextRelative;
    }
}
