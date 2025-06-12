package com.bank.ayrton.gateway.gateway_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.hc.core5.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;

//Springboot analiza todos los componentes y los gestiona el mismo
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    // Clave secreta usada para firmar/verificar el JWT (igual en todos los  servicios)
    private static final String SECRET_KEY = "CDFD54BE9758745B57BC1BEDF52C18CA3BE";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // si es login y register no pedimos token
        if (path.contains("/auth-service/login") || path.contains("/auth-service/register")) {
            return chain.filter(exchange);
        }
        // Obtenemos el header Authorization del request HTTP
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Validamos que exista el header y que comience con "Bearer " (osea que tenga token)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Si no está presente o mal formado, respondemos con 401 Unauthorized
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Extraemos solo el token JWT (removemos el prefijo "Bearer ")
        String token = authHeader.substring(7);

        try {
            // Validamos y parseamos el token con la misma clave secreta
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token); // Si falla lanza excepción

            // Si el token es válido, podemos dejar pasar el request al siguiente filtro o microservicio
            return chain.filter(exchange);

        } catch (Exception error) {
            // Si el token es inválido, caducado o está mal formado, respondemos con 401
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        // Ejecutar este filtro lo más temprano posible en la cadena de filtros
        return -1;
    }
}