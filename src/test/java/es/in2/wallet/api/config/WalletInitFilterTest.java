package es.in2.wallet.api.config;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import es.in2.wallet.infrastructure.core.config.WalletInitFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.*;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.*;

class WalletInitFilterTest {

    private CheckAndUpdateStatusCredentialsWorkflow workflow;
    private ReactiveJwtDecoder jwtDecoder;
    private WalletInitFilter filter;
    private WebFilterChain chain;

    @BeforeEach
    void setup() {
        workflow = mock(CheckAndUpdateStatusCredentialsWorkflow.class);
        jwtDecoder = mock(ReactiveJwtDecoder.class);
        filter = new WalletInitFilter(workflow, jwtDecoder);
        chain = mock(WebFilterChain.class);
    }

    @Test
    void shouldExecuteWorkflowForFirstSession() {
        String token = "mocked.jwt.token";
        String sessionState = "session123";
        String userId = "user1";

        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaimAsString("session_state")).thenReturn(sessionState);

        when(jwtDecoder.decode(token)).thenReturn(Mono.just(jwt));
        when(workflow.executeForUser(anyString(), eq(userId))).thenReturn(Mono.empty());
        when(chain.filter(any())).thenReturn(Mono.empty());

        ServerHttpRequest request = MockServerHttpRequest.get("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();

        ServerWebExchange exchange = mock(ServerWebExchange.class);
        when(exchange.getRequest()).thenReturn(request);
        when(exchange.getResponse()).thenReturn(mock(ServerHttpResponse.class));
        when(exchange.getPrincipal()).thenReturn(Mono.just(new TestingAuthenticationToken(userId, "password", "ROLE_USER")));

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(workflow, times(1)).executeForUser(anyString(), eq(userId));
    }

    @Test
    void shouldNotExecuteWorkflowIfSessionAlreadyProcessed() {
        String token = "mocked.jwt.token";
        String sessionState = "alreadyProcessed";
        String userId = "user1";

        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaimAsString("session_state")).thenReturn(sessionState);

        when(jwtDecoder.decode(token)).thenReturn(Mono.just(jwt));
        when(workflow.executeForUser(anyString(), eq(userId))).thenReturn(Mono.empty());
        when(chain.filter(any())).thenReturn(Mono.empty());

        ServerHttpRequest request = MockServerHttpRequest.get("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();

        ServerWebExchange exchange = mock(ServerWebExchange.class);
        when(exchange.getRequest()).thenReturn(request);
        when(exchange.getResponse()).thenReturn(mock(ServerHttpResponse.class));
        when(exchange.getPrincipal()).thenReturn(Mono.just(new TestingAuthenticationToken(userId, "password", "ROLE_USER")));

        filter.filter(exchange, chain).block();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(workflow, times(1)).executeForUser(anyString(), eq(userId));
    }

    @Test
    void shouldNotExecuteWorkflowIfPathDoesNotMatch() {
        ServerHttpRequest request = MockServerHttpRequest.get("/public/info").build();
        ServerWebExchange exchange = mock(ServerWebExchange.class);
        when(exchange.getRequest()).thenReturn(request);
        when(exchange.getResponse()).thenReturn(mock(ServerHttpResponse.class));
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verifyNoInteractions(jwtDecoder);
        verifyNoInteractions(workflow);
    }

    @Test
    void shouldSkipIfAuthorizationHeaderMissingOrInvalid() {
        ServerHttpRequest request = MockServerHttpRequest.get("/api/v1/credentials").build();
        ServerWebExchange exchange = mock(ServerWebExchange.class);
        when(exchange.getRequest()).thenReturn(request);
        when(exchange.getResponse()).thenReturn(mock(ServerHttpResponse.class));
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verifyNoInteractions(jwtDecoder);
        verifyNoInteractions(workflow);
    }
}
