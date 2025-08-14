package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Order(100)
@RequiredArgsConstructor
@Slf4j
public class WalletInitFilter implements WebFilter {

    private final CheckAndUpdateStatusCredentialsWorkflow checkAndUpdateStatusCredentialsWorkflow;
    private final Set<String> executedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .subscribe(auth -> {
                    String userId = auth.getName();
                    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

                    if (authHeader != null && authHeader.startsWith("Bearer ")) {
                        String token = authHeader.substring(7).trim();
                        String tokenHash = Integer.toHexString(token.hashCode());

                        if (executedTokens.add(tokenHash)) {
                            log.info("🔐 First authenticated request for token {} - executing workflow for user {}", tokenHash, userId);
                            String processId = UUID.randomUUID().toString();

                            checkAndUpdateStatusCredentialsWorkflow.executeForUser(processId, userId)
                                    .doOnError(e -> log.warn("Workflow error for {}: {}", userId, e.getMessage()))
                                    .subscribe();
                        }
                    }
                });

        return chain.filter(exchange);
    }
}
