package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@Slf4j
public class WalletInitFilter implements WebFilter, Ordered {

    private final CheckAndUpdateStatusCredentialsWorkflow workflow;
    private final Set<String> executedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public int getOrder() {
        return SecurityWebFiltersOrder.AUTHENTICATION.getOrder() + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("XIVATO 1");
        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith("/api")) {
            return chain.filter(exchange);
        }
        System.out.println("XIVATO 2");
        return chain.filter(exchange)
                .then(
                        exchange.getPrincipal()
                                .cast(Authentication.class)
                                .filter(Authentication::isAuthenticated)
                                .flatMap(auth -> {
                                    System.out.println("XIVATO 3");
                                    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
                                    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                                        return Mono.empty();
                                    }

                                    String token = authHeader.substring(7).trim();
                                    String tokenHash = Integer.toHexString(token.hashCode());

                                    if (!executedTokens.add(tokenHash)) {
                                        return Mono.empty();
                                    }

                                    String userId = auth.getName();
                                    String processId = UUID.randomUUID().toString();
                                    log.info("First authenticated request for token {}, executing workflow for user {}", tokenHash, userId);

                                    return workflow.executeForUser(processId, userId)
                                            .onErrorResume(e -> {
                                                log.warn("Workflow error for {}: {}", userId, e.getMessage());
                                                return Mono.empty();
                                            });
                                })
                );
    }
}
