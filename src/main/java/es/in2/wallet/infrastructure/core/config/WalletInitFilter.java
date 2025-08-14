package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
@RequiredArgsConstructor
public class WalletInitFilter implements WebFilter {

    private final CheckAndUpdateStatusCredentialsWorkflow workflow;
    private final Set<String> executedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
                .then(
                        ReactiveSecurityContextHolder.getContext()
                                .map(ctx -> ctx.getAuthentication())
                                .filter(Authentication::isAuthenticated)
                                .flatMap(auth -> {
                                    String userId = auth.getName();
                                    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

                                    if (authHeader != null && authHeader.startsWith("Bearer ")) {
                                        String token = authHeader.substring(7).trim();
                                        String tokenHash = Integer.toHexString(token.hashCode());

                                        if (executedTokens.add(tokenHash)) {
                                            String processId = UUID.randomUUID().toString();
                                            log.info("First access for token {}, executing workflow for user {}", tokenHash, userId);
                                            return workflow.executeForUser(processId, userId)
                                                    .doOnError(e -> log.warn("Error in workflow for {}: {}", userId, e.getMessage()))
                                                    .then();
                                        }
                                    }
                                    return Mono.empty();
                                })
                );
    }
}

