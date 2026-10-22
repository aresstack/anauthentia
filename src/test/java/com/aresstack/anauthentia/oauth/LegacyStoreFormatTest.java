package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** v1-Stores (ohne Resource-Feld) müssen weiterhin laden; gespeichert wird v2. */
class LegacyStoreFormatTest {

    @TempDir Path directory;

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void versionOneStoreLoadsWithNullResourceAndRewritesAsVersionTwo() throws Exception {
        Path file = directory.resolve("tokens.store");
        String expiry = Instant.parse("2026-06-01T00:00:00Z").toString();
        Files.write(file, ("ANAUTHENTIA_REFRESH_TOKEN_STORE\t1\n"
                + encode("legacy-token") + "\t" + encode("chatgpt") + "\t"
                + encode("mcp") + "\t" + encode(expiry) + "\n")
                .getBytes(StandardCharsets.UTF_8));

        FileRefreshTokenStore store = new FileRefreshTokenStore(file);
        Map<String, RefreshToken> loaded = store.load();
        assertEquals(1, loaded.size());
        RefreshToken token = loaded.get("legacy-token");
        assertEquals("chatgpt", token.getClientId());
        assertNull(token.getResource());

        store.save(loaded);
        String rewritten = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(rewritten.startsWith("ANAUTHENTIA_REFRESH_TOKEN_STORE\t2"));
        assertEquals(loaded, store.load());
    }
}
