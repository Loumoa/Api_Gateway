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
        // Retrieve the header value from the request
        String headerValue = exchange.getRequest().getHeaders().getFirst("Authorization");

        // Analyze the header value and validate it
        boolean isValid;
        try {
            isValid = validateHeaderValue(headerValue);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            exchange.getResponse().setStatusCode(HttpStatus.BAD_GATEWAY);
            return exchange.getResponse().setComplete();
        }

        if (isValid) {
            // If the header value is valid, continue processing the request
            return chain.filter(exchange);
        } else {
            // If the header value is invalid, reject the request with a specific HTTP status
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
    }

    private boolean validateHeaderValue(String headerValue) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Implement your custom validation logic here
        return headerValue != null && !headerValue.isEmpty() &&
                jwtUtils.validateJwtToken(headerValue);
    }
}
