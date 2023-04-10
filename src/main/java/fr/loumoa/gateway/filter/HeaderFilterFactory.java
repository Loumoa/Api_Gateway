package fr.loumoa.gateway.filter;

import fr.loumoa.gateway.security.jwt.JwtUtils;
import fr.loumoa.gateway.security.jwt.UserInfos;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedHashMap;

@Component
public class HeaderFilterFactory implements GatewayFilter {

    @Autowired
    JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String headers = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (headers != null && !headers.isEmpty()) {
            HttpHeaders newHeaders = new HttpHeaders();
            try {
                UserInfos userInfos = jwtUtils.getUserInfos(headers);
                newHeaders.set("userId", Integer.toString(userInfos.getId()));
                newHeaders.set("userName", userInfos.getName());
                newHeaders.set("userEmail", userInfos.getEmail());
                StringBuilder sb = new StringBuilder();
                if(!userInfos.getRoles().isEmpty()){
                    for (Object role :
                            userInfos.getRoles()) {
                        if (role instanceof LinkedHashMap hash){
                            sb.append(hash.get("authority")).append(",");
                        }
                    }
                    String rolesStr = sb.substring(0, sb.length() - 1).toString();
                    newHeaders.set("userRole", rolesStr);
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            ServerHttpRequest newRequest = exchange.getRequest().mutate().headers(httpHeaders -> httpHeaders.addAll(newHeaders)).build();
            return chain.filter(exchange.mutate().request(newRequest).build());
        } else {
            return chain.filter(exchange);
        }
    }
}
