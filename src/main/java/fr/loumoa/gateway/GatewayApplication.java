package fr.loumoa.gateway;

import fr.loumoa.gateway.filter.HeaderFilterFactory;
import fr.loumoa.gateway.security.CustomJwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class GatewayApplication {

    @Autowired
    CustomJwtFilter jwtFilter;

    @Autowired
    HeaderFilterFactory headerFilter;

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(p -> p
                        .path("/get")
                        .filters(f -> f.filter(jwtFilter).filter(headerFilter))
                        .uri("http://httpbin.org:80"))
                .build();
    }

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
