package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@RequiredArgsConstructor
@Slf4j
public class WalletInitFilter implements WebFilter {

    private final CheckAndUpdateStatusCredentialsWorkflow checkAndUpdateStatusCredentialsWorkflow;

    private final Set<String> executedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .flatMap(auth -> {
                    String userId = auth.getName();

                    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
                    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        return chain.filter(exchange);
                    }

                    String token = authHeader.substring(7).trim();
                    String tokenHash = Integer.toHexString(token.hashCode());

                    if (executedTokens.add(tokenHash)) {
                        log.info("First access for token {} - executing workflow for user {}", tokenHash, userId);
                        String processId = UUID.randomUUID().toString();
                        return checkAndUpdateStatusCredentialsWorkflow.executeForUser(processId, userId)
                                .onErrorResume(e -> {
                                    log.warn("Failed to execute workflow for user {}: {}", userId, e.getMessage());
                                    return Mono.empty();
                                })
                                .then(chain.filter(exchange));
                    }

                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }
}
