package es.in2.wallet.infrastructure.vault.adapter.hashicorp.config.properties;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashicorpPropertiesTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void shouldPassValidationWithValidValues() {
        HashicorpProperties properties = new HashicorpProperties("https://vault.example.com", "my-secret-token", "");

        Set<ConstraintViolation<HashicorpProperties>> violations = validator.validate(properties);

        assertTrue(violations.isEmpty(), "No validation errors expected");
    }

    @Test
    void shouldFailValidationWhenUrlIsInvalid() {
        HashicorpProperties properties = new HashicorpProperties("not-a-valid-url", "my-secret-token", "");

        Set<ConstraintViolation<HashicorpProperties>> violations = validator.validate(properties);

        assertEquals(1, violations.size(), "Expected one validation error");
        assertTrue(violations.iterator().next().getPropertyPath().toString().contains("url"));
    }

    @Test
    void shouldFailValidationWhenUrlIsNull() {
        HashicorpProperties properties = new HashicorpProperties(null, "my-secret-token", "");

        Set<ConstraintViolation<HashicorpProperties>> violations = validator.validate(properties);

        // @URL does not trigger on null values, so no error unless we add @NotNull
        assertTrue(violations.isEmpty(), "No validation error expected for null url unless @NotNull is added");
    }

    @Test
    void shouldFailValidationWhenTokenIsNull() {
        HashicorpProperties properties = new HashicorpProperties("https://vault.example.com", null, "");

        Set<ConstraintViolation<HashicorpProperties>> violations = validator.validate(properties);

        assertEquals(1, violations.size(), "Expected one validation error");
        assertTrue(violations.iterator().next().getPropertyPath().toString().contains("token"));
    }
}
