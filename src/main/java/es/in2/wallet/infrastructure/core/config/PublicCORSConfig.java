package es.in2.wallet.infrastructure.core.config;

import es.in2.wallet.application.ports.AppConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class PublicCORSConfig {

    private final AppConfig appConfig;

    /**
     * Public CORS configuration source for restricted access within the cluster.
     */
    @Bean("publicCorsSource")
    public UrlBasedCorsConfigurationSource publicCorsConfigSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(appConfig.getCorsAllowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(ENDPOINT_PIN, configuration);
        source.registerCorsConfiguration(NOTIFICATION_PIN, configuration);
        source.registerCorsConfiguration(ENDPOINT_HEALTH, configuration);
        source.registerCorsConfiguration(ENDPOINT_PROMETHEUS, configuration);

        return source;
    }
}
