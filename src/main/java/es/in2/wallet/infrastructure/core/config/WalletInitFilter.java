package es.in2.wallet.infrastructure.core.config;
import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.reactive.function.server.HandlerFilterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import lombok.RequiredArgsConstructor;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@Slf4j
public class WalletInitFilter implements HandlerFilterFunction<ServerResponse, ServerResponse> {

    private final CheckAndUpdateStatusCredentialsWorkflow workflow;
    private final Set<String> executedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public Mono<ServerResponse> filter(ServerRequest request, HandlerFunction<ServerResponse> next) {
        ServerWebExchange exchange = request.exchange();
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return next.handle(request);
        }

        String token = authHeader.substring(7).trim();
        String tokenHash = Integer.toHexString(token.hashCode());

        if (!executedTokens.add(tokenHash)) {
            return next.handle(request);
        }

        return exchange.getPrincipal()
                .cast(Authentication.class)
                .flatMap(auth -> {
                    String userId = auth.getName();
                    String processId = UUID.randomUUID().toString();
                    return workflow.executeForUser(processId, userId)
                            .doOnError(e -> log.error("Error in CheckAndUpdateStatusCredentialsWorkflow", e))
                            .then(next.handle(request));
                })
                .switchIfEmpty(next.handle(request));
    }
}
