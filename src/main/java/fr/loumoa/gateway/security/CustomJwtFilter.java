package fr.loumoa.gateway.security;

import fr.loumoa.gateway.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class CustomJwtFilter implements GatewayFilter {

    @Autowired
    JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String headerValue = exchange.getRequest().getHeaders().getFirst("Authorization");

        boolean isValid;
        try {
            isValid = validateHeaderValue(headerValue);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            exchange.getResponse().setStatusCode(HttpStatus.BAD_GATEWAY);
            return exchange.getResponse().setComplete();
        }

        if (isValid) {
            return chain.filter(exchange);
        } else {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
    }

    private boolean validateHeaderValue(String headerValue) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return headerValue != null && !headerValue.isEmpty() &&
                jwtUtils.validateJwtToken(headerValue);
    }
}
