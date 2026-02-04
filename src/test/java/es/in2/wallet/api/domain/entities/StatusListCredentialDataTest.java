package es.in2.wallet.api.domain.entities;

import es.in2.wallet.domain.entities.StatusListCredentialData;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class StatusListCredentialDataTest {

    @Test
    void constructor_whenStatusPurposeNull_throws() {
        NullPointerException ex = assertThrows(
                NullPointerException.class,
                () -> new StatusListCredentialData("issuer", null, new byte[] { 1 })
        );
        assertEquals("statusPurpose cannot be null", ex.getMessage());
    }

    @Test
    void constructor_whenRawBitstringBytesNull_throws() {
        NullPointerException ex = assertThrows(
                NullPointerException.class,
                () -> new StatusListCredentialData("issuer", "revocation", null)
        );
        assertEquals("rawBitstringBytes cannot be null", ex.getMessage());
    }

    @Test
    void constructor_clonesInputArray_defensiveCopy() {
        byte[] input = new byte[] { 1, 2, 3 };

        StatusListCredentialData data = new StatusListCredentialData("issuer", "revocation", input);

        input[0] = 99;

        assertArrayEquals(new byte[] { 1, 2, 3 }, data.rawBitstringBytes());
    }

    @Test
    void rawBitstringBytes_getterReturnsClone_defensiveCopy() {
        byte[] input = new byte[] { 10, 20, 30 };
        StatusListCredentialData data = new StatusListCredentialData("issuer", "revocation", input);

        byte[] firstRead = data.rawBitstringBytes();
        firstRead[1] = 88;

        byte[] secondRead = data.rawBitstringBytes();

        assertArrayEquals(new byte[] { 10, 20, 30 }, secondRead);
        assertNotSame(firstRead, secondRead);
    }

    @Test
    void equals_whenSameReference_true() {
        StatusListCredentialData data = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2 });
        assertEquals(data, data);
    }

    @Test
    void equals_whenNull_false() {
        StatusListCredentialData data = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2 });
        assertNotEquals(null, data);
    }

    @Test
    void equals_whenDifferentType_false() {
        StatusListCredentialData data = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2 });
        assertNotEquals("not-a-status-list", data);
    }

    @Test
    void equals_whenSameContent_true_andHashCodeMatches() {
        byte[] a1 = new byte[] { 1, 2, 3 };
        byte[] a2 = new byte[] { 1, 2, 3 };

        StatusListCredentialData d1 = new StatusListCredentialData("issuer", "revocation", a1);
        StatusListCredentialData d2 = new StatusListCredentialData("issuer", "revocation", a2);

        assertEquals(d1, d2);
        assertEquals(d1.hashCode(), d2.hashCode());
    }

    @Test
    void equals_whenIssuerDiff_false() {
        StatusListCredentialData d1 = new StatusListCredentialData("issuer-1", "revocation", new byte[] { 1, 2, 3 });
        StatusListCredentialData d2 = new StatusListCredentialData("issuer-2", "revocation", new byte[] { 1, 2, 3 });

        assertNotEquals(d1, d2);
    }

    @Test
    void equals_whenStatusPurposeDiff_false() {
        StatusListCredentialData d1 = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2, 3 });
        StatusListCredentialData d2 = new StatusListCredentialData("issuer", "suspension", new byte[] { 1, 2, 3 });

        assertNotEquals(d1, d2);
    }

    @Test
    void equals_whenArrayContentDiff_false() {
        StatusListCredentialData d1 = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2, 3 });
        StatusListCredentialData d2 = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2, 4 });

        assertNotEquals(d1, d2);
    }

    @Test
    void equals_whenSameArrayReferenceButMutatedAfterConstruction_stillUsesClonedValue() {
        byte[] raw = new byte[] { 7, 8, 9 };

        StatusListCredentialData d1 = new StatusListCredentialData("issuer", "revocation", raw);
        StatusListCredentialData d2 = new StatusListCredentialData("issuer", "revocation", raw);

        assertEquals(d1, d2);

        raw[0] = 99;

        assertEquals(d1, d2);
        assertArrayEquals(new byte[] { 7, 8, 9 }, d1.rawBitstringBytes());
        assertArrayEquals(new byte[] { 7, 8, 9 }, d2.rawBitstringBytes());
    }

    @Test
    void hashCode_whenEqualObjects_sameHashCode() {
        StatusListCredentialData d1 = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2, 3 });
        StatusListCredentialData d2 = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2, 3 });

        assertEquals(d1, d2);
        assertEquals(d1.hashCode(), d2.hashCode());
    }

    @Test
    void toString_includesIssuerPurposeAndLength_butNotRawBytesContent() {
        StatusListCredentialData data = new StatusListCredentialData("issuer", "revocation", new byte[] { 1, 2, 3, 4 });

        String s = data.toString();

        assertTrue(s.startsWith("StatusListCredentialData["));
        assertTrue(s.contains("issuer=issuer"));
        assertTrue(s.contains("statusPurpose=revocation"));
        assertTrue(s.contains("rawBitstringBytesLength=4"));

        // Ensure we don't leak array contents in toString
        assertFalse(s.contains(Arrays.toString(new byte[] { 1, 2, 3, 4 })));
        assertFalse(s.contains("1, 2, 3, 4"));
    }

    @Test
    void issuer_canBeNull_andStillWorksInEqualsHashCodeToString() {
        StatusListCredentialData d1 = new StatusListCredentialData(null, "revocation", new byte[] { 1 });
        StatusListCredentialData d2 = new StatusListCredentialData(null, "revocation", new byte[] { 1 });

        assertEquals(d1, d2);
        assertEquals(d1.hashCode(), d2.hashCode());
        assertTrue(d1.toString().contains("issuer=null"));
    }
}

