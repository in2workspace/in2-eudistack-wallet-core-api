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
        System.out.println("XIVATO1");
        return SecurityWebFiltersOrder.AUTHENTICATION.getOrder() + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("XIVATO2");
        String path = exchange.getRequest().getPath().value();

        if (!path.startsWith("/api")) {
            return chain.filter(exchange);
        }

        return chain.filter(exchange)
                .then(
                        exchange.getPrincipal()
                                .cast(Authentication.class)
                                .filter(Authentication::isAuthenticated)
                                .flatMap(auth -> {
                                    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
                                    if (authHeader == null || !authHeader.startsWith("Bearer ")) return Mono.empty();

                                    String token = authHeader.substring(7).trim();
                                    String tokenHash = Integer.toHexString(token.hashCode());

                                    if (!executedTokens.add(tokenHash)) {
                                        log.debug("Workflow already executed for token {}", tokenHash);
                                        return Mono.empty();
                                    }

                                    String userId = auth.getName();
                                    String processId = UUID.randomUUID().toString();
                                    log.info("Executing workflow after login for user {} (token {})", userId, tokenHash);

                                    return workflow.executeForUser(processId, userId)
                                            .onErrorResume(e -> {
                                                log.warn("Workflow error for user {}: {}", userId, e.getMessage());
                                                return Mono.empty();
                                            });
                                })
                );
    }
}
