package es.in2.wallet.infrastructure.core.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.WebSocketClientNotificationMessage;
import es.in2.wallet.application.dto.WebSocketServerNotificationMessage;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;

@Slf4j
@Getter
@Component
@RequiredArgsConstructor
public class NotificationRequestWebSocketHandler implements WebSocketHandler {

    private final ObjectMapper objectMapper;
    private final WebSocketSessionManager sessionManager;

    private final Map<String, Sinks.Many<String>> decisionSinks = new ConcurrentHashMap<>();
    private final Map<String, String> sessionToUserIdMap = new ConcurrentHashMap<>();

    @NotNull
    @Override
    public Mono<Void> handle(WebSocketSession session) {
        return session.receive()
                .flatMap(message -> {
                    String payload = message.getPayloadAsText();
                    try {
                        WebSocketClientNotificationMessage clientMsg =
                                objectMapper.readValue(payload, WebSocketClientNotificationMessage.class);

                        String sessionId = session.getId();

                        if (clientMsg.id() != null) {
                            return getUserIdFromToken(clientMsg.id())
                                    .doOnSuccess(userId -> {
                                        sessionManager.registerSession(userId, session);
                                        decisionSinks.putIfAbsent(userId, Sinks.many().multicast().directBestEffort());
                                        sessionToUserIdMap.put(sessionId, userId);
                                        log.debug("WS linked: sessionId={} userId={}", sessionId, userId);
                                    })
                                    .thenReturn(payload);
                        }

                        if (clientMsg.decision() != null) {
                            String userId = sessionToUserIdMap.get(sessionId);
                            if (userId == null) {
                                log.error("User ID not found for session: {}", sessionId);
                                return Mono.just(payload);
                            }

                            Sinks.Many<String> sink = decisionSinks.get(userId);
                            if (sink == null) {
                                log.error("Decision sink not found for userId={}", userId);
                                return Mono.just(payload);
                            }

                            String decision = clientMsg.decision().trim();
                            sink.tryEmitNext(decision);

                            log.info("WS decision received: userId={} decision={}", userId, decision);
                            return Mono.just(payload);
                        }

                        log.debug("WS message ignored: {}", payload);
                        return Mono.just(payload);

                    } catch (Exception e) {
                        log.error("Error processing WS message: {}", payload, e);
                        return Mono.error(new RuntimeException("Error processing message", e));
                    }
                })
                .then()
                .doFinally(signalType -> cleanUpResources(session));
    }

    public void sendNotificationDecisionRequest(WebSocketSession session, WebSocketServerNotificationMessage message) {
        try {
            String jsonMessage = objectMapper.writeValueAsString(message);
            session.send(Mono.just(session.textMessage(jsonMessage))).subscribe();
        } catch (JsonProcessingException e) {
            log.error("Error serializing WebSocketServerNotificationMessage", e);
            throw new ParseErrorException("Error serializing WebSocketServerNotificationMessage");
        }
    }

    public Flux<String> getDecisionResponses(String userId) {
        return decisionSinks
                .computeIfAbsent(userId, id -> Sinks.many().multicast().directBestEffort())
                .asFlux();
    }

    private void cleanUpResources(WebSocketSession session) {
        String sessionId = session.getId();
        String userId = sessionToUserIdMap.remove(sessionId);

        if (userId != null) {
            decisionSinks.remove(userId);
            log.debug("Cleaned up decision resources for sessionId={} userId={}", sessionId, userId);
        }
    }
}
