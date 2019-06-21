package sample;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
public class GatewayFilterFactory extends AbstractGatewayFilterFactory<GatewayFilterFactory.Config> {

    public GatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            System.out.println("************gateway filter name ");
            ServerWebExchange exchangeMutated = this.withBearerAuth(exchange);
            return chain.filter(exchangeMutated);
        };
    }

    private ServerWebExchange withBearerAuth(ServerWebExchange exchange) {
        return exchange.mutate().request((r) -> {
            r.headers((headers) -> {
                headers.setBearerAuth(String.valueOf(exchange.getResponse().getHeaders().get("x-auth-token")));
            });
        }).build();
    }

    public static class Config {

    }
}
