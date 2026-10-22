package com.aresstack.anauthentia.oauth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.nio.file.attribute.PosixFilePermission;

/**
 * File-backed refresh-token store using a versioned UTF-8 format and atomic replacement.
 *
 * <p>Fields are Base64 URL-encoded to preserve arbitrary client IDs and scopes.
 * This encoding is not encryption. Restrict access to the store file and its
 * parent directory. Use one store instance per file; coordinating multiple
 * processes requires an external locking strategy.
 */
public final class FileRefreshTokenStore implements RefreshTokenStore {

    private static final String LEGACY_HEADER = "ANAUTHENTIA_REFRESH_TOKEN_STORE\t1";
    // v2 ergänzt das RFC-8707-Resource-Feld; v1-Dateien bleiben lesbar.
    private static final String HEADER = "ANAUTHENTIA_REFRESH_TOKEN_STORE\t2";
    private static final String FIELD_SEPARATOR = "\t";
    private static final Set<PosixFilePermission> OWNER_ONLY_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));

    private final Path file;

    public FileRefreshTokenStore(Path file) {
        Objects.requireNonNull(file, "file");
        Path absoluteFile = file.toAbsolutePath().normalize();
        if (absoluteFile.getFileName() == null) {
            throw new IllegalArgumentException("file must identify a file, not a filesystem root");
        }
        this.file = absoluteFile;
    }

    @Override
    public synchronized Map<String, RefreshToken> load() {
        if (Files.notExists(file)) {
            return new LinkedHashMap<String, RefreshToken>();
        }

        try {
            return readTokens();
        } catch (IOException | RuntimeException exception) {
            throw new RefreshTokenStoreException("Unable to load refresh-token store", exception);
        }
    }

    @Override
    public synchronized void save(Map<String, RefreshToken> tokens) {
        Map<String, RefreshToken> snapshot = validateAndCopy(tokens);
        byte[] contents = serialize(snapshot);

        Path temporaryFile = null;
        try {
            Path parent = file.getParent();
            Files.createDirectories(parent);
            temporaryFile = createRestrictedTemporaryFile(parent);
            writeAndSync(temporaryFile, contents);
            replaceFile(temporaryFile);
            temporaryFile = null;
        } catch (IOException | SecurityException exception) {
            cleanupTemporaryFile(temporaryFile, exception);
            throw new RefreshTokenStoreException("Unable to persist refresh-token store", exception);
        }
    }

    private Map<String, RefreshToken> readTokens() throws IOException {
        java.util.List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        if (lines.isEmpty() || (!HEADER.equals(lines.get(0)) && !LEGACY_HEADER.equals(lines.get(0)))) {
            throw new IOException("Unsupported or invalid refresh-token store format");
        }
        boolean legacy = LEGACY_HEADER.equals(lines.get(0));

        Map<String, RefreshToken> tokens = new LinkedHashMap<String, RefreshToken>();
        for (int lineNumber = 1; lineNumber < lines.size(); lineNumber++) {
            String line = lines.get(lineNumber);
            String[] fields = line.split(FIELD_SEPARATOR, -1);
            if (fields.length != (legacy ? 4 : 5)) {
                throw new IOException("Invalid refresh-token record");
            }

            String token = decode(fields[0]);
            String clientId = decode(fields[1]);
            String scope = decode(fields[2]);
            String resource = legacy ? null : emptyToNull(decode(fields[3]));
            Instant expiresAt = Instant.parse(decode(fields[legacy ? 3 : 4]));
            if (isBlank(token)) {
                throw new IOException("Refresh-token record contains an empty token");
            }

            RefreshToken state = new RefreshToken(clientId, scope, resource, expiresAt);
            if (tokens.containsKey(token)) {
                throw new IOException("Duplicate refresh-token record");
            }
            tokens.put(token, state);
        }
        return tokens;
    }

    private Map<String, RefreshToken> validateAndCopy(Map<String, RefreshToken> tokens) {
        Objects.requireNonNull(tokens, "tokens");
        Map<String, RefreshToken> snapshot = new TreeMap<String, RefreshToken>();
        for (Map.Entry<String, RefreshToken> entry : tokens.entrySet()) {
            if (isBlank(entry.getKey())) {
                throw new IllegalArgumentException("Refresh-token keys must not be blank");
            }
            if (entry.getValue() == null) {
                throw new IllegalArgumentException("Refresh-token state must not be null");
            }
            snapshot.put(entry.getKey(), entry.getValue());
        }
        return snapshot;
    }

    private byte[] serialize(Map<String, RefreshToken> tokens) {
        StringBuilder contents = new StringBuilder(HEADER).append('\n');
        for (Map.Entry<String, RefreshToken> entry : tokens.entrySet()) {
            RefreshToken state = entry.getValue();
            contents.append(encode(entry.getKey())).append(FIELD_SEPARATOR)
                    .append(encode(state.getClientId())).append(FIELD_SEPARATOR)
                    .append(encode(state.getScope())).append(FIELD_SEPARATOR)
                    .append(encode(state.getResource() == null ? "" : state.getResource()))
                    .append(FIELD_SEPARATOR)
                    .append(encode(state.getExpiresAt().toString())).append('\n');
        }
        return contents.toString().getBytes(StandardCharsets.UTF_8);
    }

    private Path createRestrictedTemporaryFile(Path parent) throws IOException {
        String prefix = file.getFileName().toString() + ".tmp.";
        try {
            return Files.createTempFile(
                    parent,
                    prefix,
                    ".tmp",
                    PosixFilePermissions.asFileAttribute(OWNER_ONLY_PERMISSIONS));
        } catch (UnsupportedOperationException exception) {
            Path temporaryFile = Files.createTempFile(parent, prefix, ".tmp");
            try {
                restrictPermissions(temporaryFile);
                return temporaryFile;
            } catch (IOException | RuntimeException permissionException) {
                try {
                    Files.deleteIfExists(temporaryFile);
                } catch (IOException cleanupException) {
                    permissionException.addSuppressed(cleanupException);
                }
                throw permissionException;
            }
        }
    }

    private static void restrictPermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY_PERMISSIONS);
        } catch (UnsupportedOperationException exception) {
            // Rely on the operating system's inherited access-control list when POSIX permissions are unavailable.
        }
    }

    private static void writeAndSync(Path path, byte[] contents) throws IOException {
        try (FileChannel channel = FileChannel.open(
                path, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            ByteBuffer buffer = ByteBuffer.wrap(contents);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    private void replaceFile(Path temporaryFile) throws IOException {
        try {
            Files.move(
                    temporaryFile,
                    file,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(temporaryFile, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void cleanupTemporaryFile(Path temporaryFile, Exception failure) {
        if (temporaryFile == null) {
            return;
        }
        try {
            Files.deleteIfExists(temporaryFile);
        } catch (IOException | SecurityException cleanupException) {
            failure.addSuppressed(cleanupException);
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String emptyToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}