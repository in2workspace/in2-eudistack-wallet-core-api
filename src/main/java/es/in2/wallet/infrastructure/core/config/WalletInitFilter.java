package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
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

    private final CheckAndUpdateStatusCredentialsWorkflow workflow;
    private final ReactiveJwtDecoder jwtDecoder;
    private final Set<String> executedSessionStates = ConcurrentHashMap.newKeySet();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        System.out.println("XIVATO1");
        String path = exchange.getRequest().getPath().value();

        if (!path.startsWith("/api")) {
            return chain.filter(exchange);
        }
        System.out.println("XIVATO2");

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        System.out.println("XIVATO3");

        String token = authHeader.substring(7).trim();

        return exchange.getPrincipal()
                .cast(Authentication.class)
                .filter(Authentication::isAuthenticated)
                .flatMap(auth ->
                        jwtDecoder.decode(token)
                                .flatMap(jwt -> {
                                    String sessionState = jwt.getClaimAsString("session_state");
                                    if (sessionState == null || !executedSessionStates.add(sessionState)) {
                                        System.out.println("XIVATO4");
                                        return Mono.empty(); // Already executed for this session
                                    }

                                    String userId = auth.getName();
                                    String processId = UUID.randomUUID().toString();

                                    log.debug("First login for session {}, executing workflow for user {}", sessionState, userId);

                                    return workflow.executeForUser(processId, userId)
                                            .doOnError(e -> log.warn("Workflow error for {}: {}", userId, e.getMessage()))
                                            .onErrorResume(e -> Mono.empty());
                                })
                )
                .then(chain.filter(exchange));
    }
}
