package es.in2.wallet.api.ebsi.comformance.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.workflows.presentation.Oid4vpWorkflow;
import es.in2.wallet.domain.exceptions.FailedSerializingException;
import es.in2.wallet.application.dto.AuthorisationServerMetadata;
import es.in2.wallet.application.dto.PresentationDefinition;
import es.in2.wallet.application.dto.VcSelectorResponse;
import es.in2.wallet.domain.services.PresentationService;
import es.in2.wallet.domain.services.impl.EbsiVpTokenServiceImpl;
import es.in2.wallet.domain.utils.ApplicationUtils;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.Map;

import static es.in2.wallet.domain.utils.ApplicationConstants.GLOBAL_STATE;
import static es.in2.wallet.domain.utils.ApplicationUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EbsiVpTokenServiceImplTest {
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private Oid4vpWorkflow oid4vpWorkflow;
    @Mock
    private PresentationService presentationService;
    @Mock
    private WebClientConfig webClientConfig;

    @InjectMocks
    private EbsiVpTokenServiceImpl vpTokenService;

    @Test
    void testGetVpRequest() throws Exception {
        String processId = "process123";
        String authorizationToken = "ey123...";
        AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().issuer("issuer").build();
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjRjd25fSUdJM0prOFJYc21QOG5MNndEelR5ODY0S2hmNEZJcFNBX2FlTkkifQ.eyJzdGF0ZSI6IjU0NDg0YzQxLTcxNjgtNDFjNi1iZWI2LTVlMTJiYTA0NzRkNCIsImNsaWVudF9pZCI6Imh0dHBzOi8vYXBpLWNvbmZvcm1hbmNlLmVic2kuZXUvY29uZm9ybWFuY2UvdjMvYXV0aC1tb2NrIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS9jb25mb3JtYW5jZS92My9hdXRoLW1vY2svZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJzY29wZSI6Im9wZW5pZCIsIm5vbmNlIjoiZmE1MGQyMDktYmJhYy00NGVlLTkyZTQtZjZiNTViNWE5NmRhIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJob2xkZXItd2FsbGV0LXF1YWxpZmljYXRpb24tcHJlc2VudGF0aW9uIiwiZm9ybWF0Ijp7Imp3dF92cCI6eyJhbGciOlsiRVMyNTYiXX19LCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJzYW1lLWRldmljZS1hdXRob3Jpc2VkLWluLXRpbWUtY3JlZGVudGlhbCIsImZvcm1hdCI6eyJqd3RfdmMiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmMudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJDVFdhbGxldFNhbWVBdXRob3Jpc2VkSW5UaW1lIn19fV19fSx7ImlkIjoiY3Jvc3MtZGV2aWNlLWF1dGhvcmlzZWQtaW4tdGltZS1jcmVkZW50aWFsIiwiZm9ybWF0Ijp7Imp3dF92YyI6eyJhbGciOlsiRVMyNTYiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Yy50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IkNUV2FsbGV0Q3Jvc3NBdXRob3Jpc2VkSW5UaW1lIn19fV19fSx7ImlkIjoic2FtZS1kZXZpY2UtYXV0aG9yaXNlZC1kZWZlcnJlZC1jcmVkZW50aWFsIiwiZm9ybWF0Ijp7Imp3dF92YyI6eyJhbGciOlsiRVMyNTYiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Yy50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IkNUV2FsbGV0U2FtZUF1dGhvcmlzZWREZWZlcnJlZCJ9fX1dfX0seyJpZCI6ImNyb3NzLWRldmljZS1hdXRob3Jpc2VkLWRlZmVycmVkLWNyZWRlbnRpYWwiLCJmb3JtYXQiOnsiand0X3ZjIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiQ1RXYWxsZXRDcm9zc0F1dGhvcmlzZWREZWZlcnJlZCJ9fX1dfX0seyJpZCI6InNhbWUtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWluLXRpbWUtY3JlZGVudGlhbCIsImZvcm1hdCI6eyJqd3RfdmMiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmMudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJDVFdhbGxldFNhbWVQcmVBdXRob3Jpc2VkSW5UaW1lIn19fV19fSx7ImlkIjoiY3Jvc3MtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWluLXRpbWUtY3JlZGVudGlhbCIsImZvcm1hdCI6eyJqd3RfdmMiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmMudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJDVFdhbGxldENyb3NzUHJlQXV0aG9yaXNlZEluVGltZSJ9fX1dfX0seyJpZCI6InNhbWUtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWRlZmVycmVkLWNyZWRlbnRpYWwiLCJmb3JtYXQiOnsiand0X3ZjIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiQ1RXYWxsZXRTYW1lUHJlQXV0aG9yaXNlZERlZmVycmVkIn19fV19fSx7ImlkIjoiY3Jvc3MtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWRlZmVycmVkLWNyZWRlbnRpYWwiLCJmb3JtYXQiOnsiand0X3ZjIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiQ1RXYWxsZXRDcm9zc1ByZUF1dGhvcmlzZWREZWZlcnJlZCJ9fX1dfX1dfSwiaXNzIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS9jb25mb3JtYW5jZS92My9hdXRoLW1vY2siLCJhdWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm5kWXRydEV4UlVyRlZtckZTcnAzekZzRUFNQ3djZGQ3NGlWV05oSDZDRzlKSE1qVlVoYnFSM1ZUOEszMWR2bldWUHlqekRxNmRVV0E1d1EzdUpSOGc5dE04Z3VNWk0yblNQM3RwZkRrQjNxTE4zVUJzUFl1Tk5jajdFdHU1V0xNSkMiLCJleHAiOjE3MDg0MzAwODR9.n5wvBcsb0iKGFtyFI-xmS48zGW09ZxwUALYLoHTVfMX6Cp4QlJQtmG0kChSwjaAAqhWOY96ggWyJ20MKu33S8Q";
        String presentationDefinitionJson = """
                {
                    "id": "holder-wallet-qualification-presentation",
                    "format": {
                        "jwt_vp": {
                            "alg": [
                                "ES256"
                            ]
                        }
                    },
                    "input_descriptors": [
                        {
                            "id": "same-device-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSameAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "same-device-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSameAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "same-device-pre-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSamePreAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-pre-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossPreAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "same-device-pre-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSamePreAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-pre-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossPreAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;

        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            when(objectMapper.writeValueAsString(any())).thenReturn(presentationDefinitionJson);
            ObjectMapper objectMapper2 = new ObjectMapper();
            PresentationDefinition presentationDefinition = objectMapper2.readValue(presentationDefinitionJson, PresentationDefinition.class);

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just("123"));
            when(objectMapper.readValue(anyString(), eq(PresentationDefinition.class))).thenReturn(presentationDefinition);
            when(oid4vpWorkflow.getSelectableCredentialsRequiredToBuildThePresentation(eq(processId),eq(authorizationToken),anyList())).thenReturn(Flux.empty());
            when(presentationService.createSignedVerifiablePresentation(anyString(), anyString(), any(VcSelectorResponse.class), anyString(), anyString())).thenReturn(Mono.just("jwt VP"));

            ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

            // Create a mock ClientResponse for a successful response
            ClientResponse clientResponse = ClientResponse.create(HttpStatus.FOUND)
                    .header("Location", "redirect response")
                    .build();

            // Stub the exchange function to return the mock ClientResponse
            when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

            WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
            when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

            Map<String, String> map = new HashMap<>();
            map.put("code", "1234");
            map.put("state", GLOBAL_STATE);
            when(extractAllQueryParams("redirect response")).thenReturn(Mono.just(map));

            StepVerifier.create(vpTokenService.getVpRequest(processId, authorizationToken, authorisationServerMetadata, jwt))
                    .assertNext(responseMap -> {
                        assertEquals("1234", responseMap.get("code"));
                        assertEquals(GLOBAL_STATE, responseMap.get("state"));
                    })
                    .verifyComplete();

            verify(oid4vpWorkflow).getSelectableCredentialsRequiredToBuildThePresentation(eq(processId),eq(authorizationToken),anyList());
            verify(presentationService).createSignedVerifiablePresentation(anyString(), anyString(), any(VcSelectorResponse.class), anyString(), anyString());
        }
    }
    @Test
    void testGetVpRequestFailedSerializingException() throws Exception {
        String processId = "process123";
        String authorizationToken = "ey123...";
        AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().issuer("issuer").build();
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjRjd25fSUdJM0prOFJYc21QOG5MNndEelR5ODY0S2hmNEZJcFNBX2FlTkkifQ.eyJzdGF0ZSI6IjU0NDg0YzQxLTcxNjgtNDFjNi1iZWI2LTVlMTJiYTA0NzRkNCIsImNsaWVudF9pZCI6Imh0dHBzOi8vYXBpLWNvbmZvcm1hbmNlLmVic2kuZXUvY29uZm9ybWFuY2UvdjMvYXV0aC1tb2NrIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS9jb25mb3JtYW5jZS92My9hdXRoLW1vY2svZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJzY29wZSI6Im9wZW5pZCIsIm5vbmNlIjoiZmE1MGQyMDktYmJhYy00NGVlLTkyZTQtZjZiNTViNWE5NmRhIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJob2xkZXItd2FsbGV0LXF1YWxpZmljYXRpb24tcHJlc2VudGF0aW9uIiwiZm9ybWF0Ijp7Imp3dF92cCI6eyJhbGciOlsiRVMyNTYiXX19LCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJzYW1lLWRldmljZS1hdXRob3Jpc2VkLWluLXRpbWUtY3JlZGVudGlhbCIsImZvcm1hdCI6eyJqd3RfdmMiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmMudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJDVFdhbGxldFNhbWVBdXRob3Jpc2VkSW5UaW1lIn19fV19fSx7ImlkIjoiY3Jvc3MtZGV2aWNlLWF1dGhvcmlzZWQtaW4tdGltZS1jcmVkZW50aWFsIiwiZm9ybWF0Ijp7Imp3dF92YyI6eyJhbGciOlsiRVMyNTYiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Yy50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IkNUV2FsbGV0Q3Jvc3NBdXRob3Jpc2VkSW5UaW1lIn19fV19fSx7ImlkIjoic2FtZS1kZXZpY2UtYXV0aG9yaXNlZC1kZWZlcnJlZC1jcmVkZW50aWFsIiwiZm9ybWF0Ijp7Imp3dF92YyI6eyJhbGciOlsiRVMyNTYiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Yy50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IkNUV2FsbGV0U2FtZUF1dGhvcmlzZWREZWZlcnJlZCJ9fX1dfX0seyJpZCI6ImNyb3NzLWRldmljZS1hdXRob3Jpc2VkLWRlZmVycmVkLWNyZWRlbnRpYWwiLCJmb3JtYXQiOnsiand0X3ZjIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiQ1RXYWxsZXRDcm9zc0F1dGhvcmlzZWREZWZlcnJlZCJ9fX1dfX0seyJpZCI6InNhbWUtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWluLXRpbWUtY3JlZGVudGlhbCIsImZvcm1hdCI6eyJqd3RfdmMiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmMudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJDVFdhbGxldFNhbWVQcmVBdXRob3Jpc2VkSW5UaW1lIn19fV19fSx7ImlkIjoiY3Jvc3MtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWluLXRpbWUtY3JlZGVudGlhbCIsImZvcm1hdCI6eyJqd3RfdmMiOnsiYWxnIjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmMudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJDVFdhbGxldENyb3NzUHJlQXV0aG9yaXNlZEluVGltZSJ9fX1dfX0seyJpZCI6InNhbWUtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWRlZmVycmVkLWNyZWRlbnRpYWwiLCJmb3JtYXQiOnsiand0X3ZjIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiQ1RXYWxsZXRTYW1lUHJlQXV0aG9yaXNlZERlZmVycmVkIn19fV19fSx7ImlkIjoiY3Jvc3MtZGV2aWNlLXByZS1hdXRob3Jpc2VkLWRlZmVycmVkLWNyZWRlbnRpYWwiLCJmb3JtYXQiOnsiand0X3ZjIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiQ1RXYWxsZXRDcm9zc1ByZUF1dGhvcmlzZWREZWZlcnJlZCJ9fX1dfX1dfSwiaXNzIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS9jb25mb3JtYW5jZS92My9hdXRoLW1vY2siLCJhdWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm5kWXRydEV4UlVyRlZtckZTcnAzekZzRUFNQ3djZGQ3NGlWV05oSDZDRzlKSE1qVlVoYnFSM1ZUOEszMWR2bldWUHlqekRxNmRVV0E1d1EzdUpSOGc5dE04Z3VNWk0yblNQM3RwZkRrQjNxTE4zVUJzUFl1Tk5jajdFdHU1V0xNSkMiLCJleHAiOjE3MDg0MzAwODR9.n5wvBcsb0iKGFtyFI-xmS48zGW09ZxwUALYLoHTVfMX6Cp4QlJQtmG0kChSwjaAAqhWOY96ggWyJ20MKu33S8Q";
        String presentationDefinitionJson = """
                {
                    "id": "holder-wallet-qualification-presentation",
                    "format": {
                        "jwt_vp": {
                            "alg": [
                                "ES256"
                            ]
                        }
                    },
                    "input_descriptors": [
                        {
                            "id": "same-device-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSameAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "same-device-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSameAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "same-device-pre-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSamePreAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-pre-authorised-in-time-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossPreAuthorisedInTime"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "same-device-pre-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletSamePreAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "id": "cross-device-pre-authorised-deferred-credential",
                            "format": {
                                "jwt_vc": {
                                    "alg": [
                                        "ES256"
                                    ]
                                }
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.type"
                                        ],
                                        "filter": {
                                            "type": "array",
                                            "contains": {
                                                "const": "CTWalletCrossPreAuthorisedDeferred"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;

        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            when(objectMapper.writeValueAsString(any()))
                    .thenReturn(presentationDefinitionJson)
                    .thenThrow(new JsonProcessingException("Deserialization error"){});

            ObjectMapper objectMapper2 = new ObjectMapper();
            PresentationDefinition presentationDefinition = objectMapper2.readValue(presentationDefinitionJson, PresentationDefinition.class);

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just("123"));
            when(objectMapper.readValue(anyString(), eq(PresentationDefinition.class))).thenReturn(presentationDefinition);
            when(oid4vpWorkflow.getSelectableCredentialsRequiredToBuildThePresentation(eq(processId),eq(authorizationToken),anyList())).thenReturn(Flux.empty());
            when(presentationService.createSignedVerifiablePresentation(anyString(), anyString(), any(VcSelectorResponse.class), anyString(), anyString())).thenReturn(Mono.just("jwt VP"));


            StepVerifier.create(vpTokenService.getVpRequest(processId, authorizationToken, authorisationServerMetadata, jwt))
                    .expectError(FailedSerializingException.class)
                    .verify();

        }
    }
}
