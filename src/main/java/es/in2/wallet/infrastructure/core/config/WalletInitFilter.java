package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
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
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("Executing WalletInitFilter");
        String path = exchange.getRequest().getPath().value();

        if (!path.startsWith("/api/v1/credentials")) {
            return chain.filter(exchange);
        }

        return exchange.getPrincipal()
                .cast(Authentication.class)
                .filter(Authentication::isAuthenticated)
                .flatMap(auth -> {
                    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

                    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        return chain.filter(exchange);
                    }

                    String token = authHeader.substring(7).trim();
                    String tokenHash = Integer.toHexString(token.hashCode());

                    if (!executedTokens.add(tokenHash)) {
                        return chain.filter(exchange);
                    }

                    String userId = auth.getName();
                    String processId = UUID.randomUUID().toString();
                    log.info("Triggered workflow for user {} at /credentials with token {}", userId, tokenHash);

                    return workflow.executeForUser(processId, userId)
                            .doOnError(e -> log.warn("Workflow error for user {}: {}", userId, e.getMessage()))
                            .then(chain.filter(exchange));
                })
                .switchIfEmpty(chain.filter(exchange));
    }
}
