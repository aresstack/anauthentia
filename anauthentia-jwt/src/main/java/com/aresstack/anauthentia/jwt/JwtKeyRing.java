package com.aresstack.anauthentia.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable set of RSA signing keys: one current signing key plus retired
 * keys that remain valid for verification until their tokens expire.
 *
 * <p>Rotation produces a new ring; hosts persist the private keys themselves
 * (e.g. DPAPI-protected) and publish {@link #publicJwkSet()} as JWKS.
 */
public final class JwtKeyRing {

    private static final int KEY_SIZE_BITS = 2048;

    private final RSAKey currentKey;
    private final List<RSAKey> retiredKeys;

    private JwtKeyRing(RSAKey currentKey, List<RSAKey> retiredKeys) {
        this.currentKey = currentKey;
        this.retiredKeys = Collections.unmodifiableList(new ArrayList<RSAKey>(retiredKeys));
    }

    /** Generate a fresh ring with a single 2048-bit RS256 signing key. */
    public static JwtKeyRing generate(String keyId) {
        return new JwtKeyRing(generateKey(keyId), Collections.<RSAKey>emptyList());
    }

    /** Recreate a ring from persisted keys (current first, retired after). */
    public static JwtKeyRing of(RSAKey currentKey, List<RSAKey> retiredKeys) {
        Objects.requireNonNull(currentKey, "currentKey");
        Objects.requireNonNull(retiredKeys, "retiredKeys");
        requireUsableSigningKey(currentKey);
        return new JwtKeyRing(currentKey, retiredKeys);
    }

    /**
     * Rotate to a fresh signing key. The previous current key is retained for
     * verification so already issued tokens stay valid until they expire.
     */
    public JwtKeyRing rotate(String newKeyId) {
        List<RSAKey> nextRetired = new ArrayList<RSAKey>(retiredKeys);
        nextRetired.add(0, currentKey);
        return new JwtKeyRing(generateKey(newKeyId), nextRetired);
    }

    public RSAKey currentKey() {
        return currentKey;
    }

    public String currentKeyId() {
        return currentKey.getKeyID();
    }

    public List<RSAKey> retiredKeys() {
        return retiredKeys;
    }

    /** All keys of the ring (current + retired) as public-only JWKS. */
    public JWKSet publicJwkSet() {
        List<RSAKey> publicKeys = new ArrayList<RSAKey>();
        publicKeys.add(currentKey.toPublicJWK());
        for (RSAKey retired : retiredKeys) {
            publicKeys.add(retired.toPublicJWK());
        }
        return new JWKSet(new ArrayList<com.nimbusds.jose.jwk.JWK>(publicKeys));
    }

    /** JWKS JSON containing only public key material. */
    public String publicJwksJson() {
        return publicJwkSet().toString(true);
    }

    private static RSAKey generateKey(String keyId) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("keyId must not be blank");
        }
        try {
            return new RSAKeyGenerator(KEY_SIZE_BITS)
                    .keyID(keyId)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to generate an RSA signing key", exception);
        }
    }

    private static void requireUsableSigningKey(RSAKey key) {
        if (!key.isPrivate()) {
            throw new IllegalArgumentException("currentKey must contain the private key");
        }
        if (key.getKeyID() == null || key.getKeyID().trim().isEmpty()) {
            throw new IllegalArgumentException("currentKey must carry a kid");
        }
    }
}
