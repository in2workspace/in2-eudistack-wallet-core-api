package es.in2.wallet.api.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.WebSocketClientNotificationMessage;
import es.in2.wallet.application.dto.WebSocketServerNotificationMessage;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.infrastructure.core.config.NotificationRequestWebSocketHandler;
import es.in2.wallet.infrastructure.core.config.WebSocketSessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationRequestWebSocketHandlerTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private WebSocketSessionManager sessionManager;

    @InjectMocks
    private NotificationRequestWebSocketHandler handler;

    @Mock
    private WebSocketSession session;

    @BeforeEach
    void setUp() {
        handler = new NotificationRequestWebSocketHandler(objectMapper, sessionManager);
    }

    @Test
    void testHandleIdMessage() throws Exception {
        String jwtToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxOGFyVmZaZTJpQkJoaU56RURnT3c3Tlc1ZmZHNElLTEtOSmVIOFQxdjJNIn0.eyJleHAiOjE3MTgzNjU3MjUsImlhdCI6MTcxODM2NTQyNSwiYXV0aF90aW1lIjoxNzE4MzUyODA1LCJqdGkiOiJlZWFmNWRlNy0wODc5LTRkYTktOGMwYS0yMGIzZDIwNWZjNGIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjcwMDIvcmVhbG1zL3dhbGxldCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyYzk5NTFkMi04NmNjLTQ0ZGYtOGQ2Mi0zNDIyN2NmYmVmOWMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhdXRoLWNsaWVudCIsIm5vbmNlIjoiYjVkZGVhZDE3ZGU2YjhmNzkyZDZkN2MwMzY4NTFlZjU3MGdRRjlxdDIiLCJzZXNzaW9uX3N0YXRlIjoiNjBkYjRiM2UtM2MzMi00NGY2LTk0YzItZGEzOGYyNTFmODc5IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjQyMDIiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIiwiZGVmYXVsdC1yb2xlcy13YWxsZXQiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBvZmZsaW5lX2FjY2VzcyBlbWFpbCBwcm9maWxlIiwic2lkIjoiNjBkYjRiM2UtM2MzMi00NGY2LTk0YzItZGEzOGYyNTFmODc5IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoidXNlciB3YWxsZXQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyIiwiZ2l2ZW5fbmFtZSI6InVzZXIiLCJmYW1pbHlfbmFtZSI6IndhbGxldCIsImVtYWlsIjoidXNlcndhbGxldEBleGFtcGxlLmNvbSJ9.iQCM2Yxlw68-6r2aIM1XAU9aT_fK7dMOliwTX_wwZhORmk3D8qkFBLfg_6JnWyFE0lRYq_NP__mJZXneXFbnjWkXsEN4WyuuIzb-jRc1REu9A0b40N3Gt-JfjU1GEKw-4SkrG8tUsgM6lxCI0DEP1_V9z47YwDRkT50DzdtwBMa7aKQ3f3o3Cla_fCG2c0CKk6LsCYi9wOth2dEknRhqaEwwk1BXopsScE1hqB-evY-sYjETEK081tXaAbk5Mdsbp7tdWTsRoVhaDGSOB6ZzlKVscGP8KWPjD6DSmKfEGaLG7X8lKXMqhMaeT9UpgXGtWzi7Ey9E7OstB0APLhaoEA";

        String payload = """
                {
                    "id": "%s"
                }
                """.formatted(jwtToken);

        WebSocketClientNotificationMessage message = new WebSocketClientNotificationMessage(jwtToken, null);
        WebSocketMessage webSocketMessage = mock(WebSocketMessage.class);

        when(webSocketMessage.getPayloadAsText()).thenReturn(payload);
        when(session.receive()).thenReturn(Flux.just(webSocketMessage));
        when(objectMapper.readValue(payload, WebSocketClientNotificationMessage.class)).thenReturn(message);
        when(session.getId()).thenReturn("sessionId");

        StepVerifier.create(handler.handle(session))
                .verifyComplete();
    }

    @Test
    void testHandleDecisionMessage() throws Exception {
        String payload = "{\"decision\":\"true\"}";
        WebSocketClientNotificationMessage message = new WebSocketClientNotificationMessage(null, "true");
        WebSocketMessage webSocketMessage = mock(WebSocketMessage.class);

        when(webSocketMessage.getPayloadAsText()).thenReturn(payload);
        when(session.receive()).thenReturn(Flux.just(webSocketMessage));
        when(objectMapper.readValue(payload, WebSocketClientNotificationMessage.class)).thenReturn(message);
        when(session.getId()).thenReturn("sessionId");

        handler.getSessionToUserIdMap().put("sessionId", "testUser");
        Sinks.Many<String> sink = Sinks.many().multicast().directBestEffort();
        handler.getDecisionSinks().put("testUser", sink);

        StepVerifier.create(handler.handle(session))
                .then(sink::tryEmitComplete)
                .verifyComplete();

        StepVerifier.create(sink.asFlux())
                .verifyComplete();
    }

    @Test
    void testSendNotificationDecisionRequest() throws JsonProcessingException {
        WebSocketServerNotificationMessage serverMessage =
                new WebSocketServerNotificationMessage(true, null, 30_000L, 1_700_000_000L);

        WebSocketMessage webSocketMessage = mock(WebSocketMessage.class);
        String jsonMessage = "{\"decision\":true,\"timeout\":30000,\"expiresAt\":1700000000}";

        when(objectMapper.writeValueAsString(serverMessage)).thenReturn(jsonMessage);
        when(session.textMessage(jsonMessage)).thenReturn(webSocketMessage);
        when(session.send(any())).thenReturn(Mono.empty());

        handler.sendNotificationDecisionRequest(session, serverMessage);

        verify(session, times(1)).send(any());
    }

    @Test
    void testSendNotificationDecisionRequestSerializationError() throws JsonProcessingException {
        WebSocketServerNotificationMessage serverMessage =
                new WebSocketServerNotificationMessage(true, null, 30_000L, 1_700_000_000L);

        when(objectMapper.writeValueAsString(serverMessage)).thenThrow(JsonProcessingException.class);

        assertThrows(ParseErrorException.class,
                () -> handler.sendNotificationDecisionRequest(session, serverMessage));

        verify(session, never()).send(any());
    }

    @Test
    void testGetDecisionResponses() {
        String userId = "testUser";
        Sinks.Many<String> sink = Sinks.many().multicast().directBestEffort();
        handler.getDecisionSinks().put(userId, sink);

        Flux<String> responses = handler.getDecisionResponses(userId);

        StepVerifier.create(responses)
                .then(() -> sink.tryEmitNext("true"))
                .expectNext("true")
                .thenCancel()
                .verify();
    }

    @Test
    void testGetDecisionResponsesNoSink() {
        String userId = "unknownUser";

        Flux<String> responses = handler.getDecisionResponses(userId);

        StepVerifier.create(responses)
                .thenCancel()
                .verify();
    }
}

