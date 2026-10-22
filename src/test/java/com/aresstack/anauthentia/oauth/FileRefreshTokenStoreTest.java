package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileRefreshTokenStoreTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void persistsAndRestoresRefreshTokensAcrossStoreInstances() {
        Path file = temporaryDirectory.resolve("state").resolve("refresh-tokens.dat");
        FileRefreshTokenStore firstStore = new FileRefreshTokenStore(file);
        Map<String, RefreshToken> tokens = new LinkedHashMap<String, RefreshToken>();
        tokens.put("opaque-refresh-token", new RefreshToken(
                "client\tid", "mcp\tread", Instant.parse("2026-12-31T23:59:59Z")));

        firstStore.save(tokens);

        Map<String, RefreshToken> restored = new FileRefreshTokenStore(file).load();

        assertEquals(tokens, restored);
        assertTrue(Files.exists(file));
    }

    @Test
    void replacesTheCompleteSnapshotInsteadOfLeavingRevokedTokensBehind() {
        Path file = temporaryDirectory.resolve("refresh-tokens.dat");
        FileRefreshTokenStore store = new FileRefreshTokenStore(file);
        Map<String, RefreshToken> original = new LinkedHashMap<String, RefreshToken>();
        original.put("old-token", new RefreshToken(
                "client", "mcp", Instant.parse("2026-12-31T23:59:59Z")));
        store.save(original);

        Map<String, RefreshToken> replacement = new LinkedHashMap<String, RefreshToken>();
        replacement.put("new-token", new RefreshToken(
                "client", "mcp", Instant.parse("2027-01-01T00:00:00Z")));
        store.save(replacement);

        Map<String, RefreshToken> restored = store.load();
        assertEquals(Collections.singleton("new-token"), restored.keySet());
        assertFalse(restored.containsKey("old-token"));
    }

    @Test
    void returnsAnEmptySnapshotWhenTheFileDoesNotExist() {
        FileRefreshTokenStore store = new FileRefreshTokenStore(
                temporaryDirectory.resolve("missing.dat"));

        assertTrue(store.load().isEmpty());
    }

    @Test
    void rejectsCorruptStoreContentsInsteadOfTreatingThemAsAnEmptyStore() throws IOException {
        Path file = temporaryDirectory.resolve("corrupt.dat");
        Files.write(file, Collections.singletonList("not-a-valid-store"), StandardCharsets.UTF_8);
        FileRefreshTokenStore store = new FileRefreshTokenStore(file);

        RefreshTokenStoreException exception = assertThrows(
                RefreshTokenStoreException.class, store::load);

        assertFalse(exception.getMessage().contains("opaque-refresh-token"));
    }

    @Test
    void rejectsNullSnapshotsBeforeWriting() {
        FileRefreshTokenStore store = new FileRefreshTokenStore(
                temporaryDirectory.resolve("refresh-tokens.dat"));

        assertThrows(NullPointerException.class, () -> store.save(null));
        assertFalse(Files.exists(temporaryDirectory.resolve("refresh-tokens.dat")));
    }
}