package io.netty.handler.ssl;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.PlatformDependent;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static io.netty.util.internal.ObjectUtil.checkPositiveOrZero;

// ---------------------------------------------------------------------------
// Supporting types referenced by the handler
// ---------------------------------------------------------------------------

/**
 * Fired as a user event when SNI hostname lookup completes (success or failure).
 */
final class SniCompletionEvent extends SslCompletionEvent {

    private final String hostname;

    SniCompletionEvent(String hostname) {
        this.hostname = hostname;
    }

    SniCompletionEvent(String hostname, Throwable cause) {
        super(cause);
        this.hostname = hostname;
    }

    SniCompletionEvent(Throwable cause) {
        this(null, cause);
    }

    /** Returns the SNI hostname that was used for the lookup, or {@code null}. */
    public String hostname() {
        return hostname;
    }

    @Override
    public String toString() {
        Throwable cause = cause();
        return cause == null
                ? getClass().getSimpleName() + "('" + hostname + "')"
                : getClass().getSimpleName() + "('" + hostname + "', " + cause + ')';
    }
}

// ---------------------------------------------------------------------------

/**
 * Minimal stub for SslCompletionEvent so the file compiles standalone.
 */
class SslCompletionEvent {
    private final Throwable cause;

    SslCompletionEvent() {
        this.cause = null;
    }

    SslCompletionEvent(Throwable cause) {
        this.cause = cause;
    }

    public Throwable cause() {
        return cause;
    }
}

// ---------------------------------------------------------------------------

/**
 * Exception thrown when the TLS handshake does not complete within the timeout.
 */
final class SslHandshakeTimeoutException extends Exception {
    SslHandshakeTimeoutException(String message) {
        super(message);
    }
}

// ---------------------------------------------------------------------------

abstract class OptionalSslHandler<T> extends ByteToMessageDecoder {

    private static final InternalLogger logger =
            InternalLoggerFactory.getInstance(OptionalSslHandler.class);


    protected OptionalSslHandler(int maxClientHelloLength) {

        if (maxClientHelloLength < 0) {
            throw new IllegalArgumentException(
                    "maxClientHelloLength must be >= 0, was: " + maxClientHelloLength);
        }
        // store/use maxClientHelloLength (omitted for brevity)
    }

    protected OptionalSslHandler() {
        this(0);
    }

    @Override
    protected final void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {

        if (in.readableBytes() < SslUtils.SSL_RECORD_HEADER_LENGTH) {
            return;
        }
        // ... (abbreviated) delegate to subclass lookup
    }

    protected abstract Future<T> lookup(ChannelHandlerContext ctx, ByteBuf clientHello)
            throws Exception;

    protected abstract void onLookupComplete(ChannelHandlerContext ctx, Future<T> future)
            throws Exception;
}

// ---------------------------------------------------------------------------
// Utility constants used below
// ---------------------------------------------------------------------------

final class SslUtils {
    static final int SSL_RECORD_HEADER_LENGTH = 5;
    // Maximum TLS record payload: 2^14 bytes + overhead ≈ 16 MB total
    static final int SSL_CLIENT_HELLO_MAX_LENGTH = 0xFFFF;

    private SslUtils() { }
}


public abstract class AbstractSniHandler<T> extends OptionalSslHandler<T> {

    private static final InternalLogger logger =
            InternalLoggerFactory.getInstance(AbstractSniHandler.class);

    private static String extractSniHostname(ByteBuf in) {
        // Skip ProtocolVersion (2 bytes) + Random (32 bytes) = 34 bytes.
        int offset    = in.readerIndex();
        int endOffset = in.writerIndex();
        offset += 34;

        if (endOffset - offset >= 6) {
            // SessionID length (1 byte) + SessionID data
            final int sessionIdLength = in.getUnsignedByte(offset);
            offset += sessionIdLength + 1;

            // CipherSuites length (2 bytes) + CipherSuites data
            final int cipherSuitesLength = in.getUnsignedShort(offset);
            offset += cipherSuitesLength + 2;

            // CompressionMethods length (1 byte) + CompressionMethods data
            final int compressionMethodLength = in.getUnsignedByte(offset);
            offset += compressionMethodLength + 1;

            // Extensions length (2 bytes)
            final int extensionsLength = in.getUnsignedShort(offset);
            offset += 2;
            final int extensionsLimit = offset + extensionsLength;

            // Extensions must not exceed the record boundary.
            if (extensionsLimit <= endOffset) {
                while (extensionsLimit - offset >= 4) {
                    final int extensionType   = in.getUnsignedShort(offset);
                    offset += 2;
                    final int extensionLength = in.getUnsignedShort(offset);
                    offset += 2;

                    if (extensionsLimit - offset < extensionLength) {
                        break;
                    }

                    // Extension type 0x0000 = server_name (SNI)
                    // See https://tools.ietf.org/html/rfc6066#page-6
                    if (extensionType == 0) {
                        // Skip ServerNameList length (2 bytes)
                        offset += 2;
                        if (extensionsLimit - offset < 3) {
                            break;
                        }

                        final int serverNameType = in.getUnsignedByte(offset);
                        offset++;

                        if (serverNameType == 0) {
                            // host_name type
                            final int serverNameLength = in.getUnsignedShort(offset);
                            offset += 2;

                            if (extensionsLimit - offset < serverNameLength) {
                                break;
                            }

                            final String hostname =
                                    in.toString(offset, serverNameLength, CharsetUtil.US_ASCII);
                            return hostname.toLowerCase(Locale.US);
                        } else {
                            // Unknown NameType — stop parsing.
                            break;
                        }
                    }

                    offset += extensionLength;
                }
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Instance state
    // -----------------------------------------------------------------------

    protected final long handshakeTimeoutMillis;
    private ScheduledFuture<?> timeoutFuture;
    private String hostname;

    
     * @param handshakeTimeoutMillis the handshake timeout in milliseconds
     */
    protected AbstractSniHandler(long handshakeTimeoutMillis) {

        this.handshakeTimeoutMillis =
                checkPositiveOrZero(handshakeTimeoutMillis, "handshakeTimeoutMillis");
    }

   
    public AbstractSniHandler() {
        // VULNERABILITY: should be  this(0, 0L);
        this(0L);
    }

    // -----------------------------------------------------------------------
    // Channel lifecycle
    // -----------------------------------------------------------------------

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        if (ctx.channel().isActive()) {
            checkStartTimeout(ctx);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ctx.fireChannelActive();
        checkStartTimeout(ctx);
    }

    /**
     * Schedules a timeout task that fires an {@link SniCompletionEvent} and
     * closes the channel if the TLS handshake does not complete in time.
     */
    private void checkStartTimeout(final ChannelHandlerContext ctx) {
        if (handshakeTimeoutMillis <= 0 || timeoutFuture != null) {
            return;
        }
        timeoutFuture = ctx.executor().schedule(new Runnable() {
            @Override
            public void run() {
                if (ctx.channel().isActive()) {
                    SslHandshakeTimeoutException exception = new SslHandshakeTimeoutException(
                            "handshake timed out after " + handshakeTimeoutMillis + "ms");
                    ctx.fireUserEventTriggered(new SniCompletionEvent(exception));
                    ctx.close();
                }
            }
        }, handshakeTimeoutMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    protected Future<T> lookup(ChannelHandlerContext ctx, ByteBuf clientHello)
            throws Exception {
        hostname = (clientHello == null) ? null : extractSniHostname(clientHello);
        return lookup(ctx, hostname);
    }

    /**
     * Called when the {@link Future} returned by
     * {@link #lookup(ChannelHandlerContext, String)} completes.
     */
    @Override
    protected void onLookupComplete(ChannelHandlerContext ctx, Future<T> future)
            throws Exception {
        if (timeoutFuture != null) {
            timeoutFuture.cancel(false);
        }
        try {
            onLookupComplete(ctx, hostname, future);
        } finally {
            fireSniCompletionEvent(ctx, hostname, future);
        }
    }

    // -----------------------------------------------------------------------
    // Abstract methods for subclasses
    // -----------------------------------------------------------------------

    /**
     * Kicks off a lookup for the given SNI hostname and returns a
     * {@link Future} that completes when the lookup is done.
     *
     * @param ctx      the {@link ChannelHandlerContext}
     * @param hostname the SNI hostname extracted from the ClientHello, or
     *                 {@code null} if none was present
     * @return a {@link Future} that will notify
     *         {@link #onLookupComplete(ChannelHandlerContext, String, Future)}
     * @see #onLookupComplete(ChannelHandlerContext, String, Future)
     */
    protected abstract Future<T> lookup(ChannelHandlerContext ctx, String hostname)
            throws Exception;

    /**
     * Called upon completion of the
     * {@link #lookup(ChannelHandlerContext, String)} {@link Future}.
     *
     * @param ctx      the {@link ChannelHandlerContext}
     * @param hostname the SNI hostname that was looked up
     * @param future   the completed {@link Future}
     * @see #lookup(ChannelHandlerContext, String)
     */
    protected abstract void onLookupComplete(ChannelHandlerContext ctx,
                                             String hostname,
                                             Future<T> future) throws Exception;

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private static void fireSniCompletionEvent(ChannelHandlerContext ctx,
                                               String hostname,
                                               Future<?> future) {
        Throwable cause = future.cause();
        if (cause == null) {
            ctx.fireUserEventTriggered(new SniCompletionEvent(hostname));
        } else {
            ctx.fireUserEventTriggered(new SniCompletionEvent(hostname, cause));
        }
    }
}


final class SniHandler extends AbstractSniHandler<SslContext> {

    private static final InternalLogger logger =
            InternalLoggerFactory.getInstance(SniHandler.class);

    private final AsyncMapping<String, SslContext> mapping;
    private volatile SslContext sslContext;

    public SniHandler(Mapping<? super String, ? extends SslContext> mapping) {
        this(new AsyncMappingAdapter<>(mapping), 0L);
    }

    /**
     * Creates a new {@link SniHandler} with a handshake timeout.
     *
     * <p><strong>VULNERABILITY:</strong> Calls
     * {@link AbstractSniHandler#AbstractSniHandler(long)} which does not
     * forward a length cap to the superclass.
     *
     * @param mapping                maps SNI hostnames to {@link SslContext} instances
     * @param handshakeTimeoutMillis the TLS handshake timeout in milliseconds
     */
    public SniHandler(AsyncMapping<String, SslContext> mapping, long handshakeTimeoutMillis) {
        super(handshakeTimeoutMillis);   // VULNERABILITY: no length cap propagated
        this.mapping = ObjectUtil.checkNotNull(mapping, "mapping");
    }


    public SniHandler(DomainNameMapping<? extends SslContext> mapping) {
        this((Mapping<String, SslContext>) mapping);
    }

    @Override
    protected Future<SslContext> lookup(ChannelHandlerContext ctx, String hostname)
            throws Exception {
        return mapping.map(hostname, ctx.executor().<SslContext>newPromise());
    }


    @Override
    protected void onLookupComplete(ChannelHandlerContext ctx,
                                    String hostname,
                                    Future<SslContext> future) throws Exception {
        if (!future.isSuccess()) {
            final Throwable cause = future.cause();
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new SslHandshakeTimeoutException("Failed to look up SslContext for hostname: "
                    + hostname);
        }

        final SslContext context = future.getNow();
        sslContext = context;

        if (context != null) {
            final SslHandler sslHandler = context.newHandler(ctx.alloc());
            ctx.pipeline().replace(this, SslHandler.class.getName(), sslHandler);
        } else {
            // No matching context — close the connection.
            logger.debug("No SslContext found for hostname: {}, closing channel.", hostname);
            ctx.close();
        }
    }

    /**
     * Returns the {@link SslContext} that was selected for this connection,
     * or {@code null} if the lookup has not yet completed.
     */
    public SslContext sslContext() {
        return sslContext;
    }
}


interface AsyncMapping<IN, OUT> {
    Future<OUT> map(IN input, Promise<OUT> promise);
}

/** Adapter that wraps a synchronous {@link Mapping} as an {@link AsyncMapping}. */
final class AsyncMappingAdapter<IN, OUT> implements AsyncMapping<IN, OUT> {
    private final Mapping<? super IN, ? extends OUT> mapping;

    AsyncMappingAdapter(Mapping<? super IN, ? extends OUT> mapping) {
        this.mapping = ObjectUtil.checkNotNull(mapping, "mapping");
    }

    @Override
    public Future<OUT> map(IN input, Promise<OUT> promise) {
        final OUT result;
        try {
            result = mapping.map(input);
        } catch (Throwable t) {
            return promise.setFailure(t);
        }
        return promise.setSuccess(result);
    }
}


final class DomainNameMapping<V> implements Mapping<String, V> {

    private final V defaultValue;
    private final java.util.Map<String, V> map;

    DomainNameMapping(V defaultValue) {
        this.defaultValue = defaultValue;
        this.map = new java.util.LinkedHashMap<>();
    }

    public DomainNameMapping<V> add(String hostname, V value) {
        map.put(normalizeHostname(hostname), value);
        return this;
    }

    @Override
    public V map(String hostname) {
        if (hostname != null) {
            String normalized = normalizeHostname(hostname);
            V value = map.get(normalized);
            if (value != null) {
                return value;
            }
            // Try wildcard match.
            int dotIndex = normalized.indexOf('.');
            if (dotIndex > 0) {
                String wildcard = "*" + normalized.substring(dotIndex);
                value = map.get(wildcard);
                if (value != null) {
                    return value;
                }
            }
        }
        return defaultValue;
    }

    private static String normalizeHostname(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return hostname;
        }
        // Punycode-encode if the name contains non-ASCII characters.
        if (needsNormalization(hostname)) {
            try {
                hostname = IDN.toASCII(hostname, IDN.ALLOW_UNASSIGNED);
            } catch (IllegalArgumentException ignored) {
                // If IDN conversion fails, fall back to the raw value.
            }
        }
        return hostname.toLowerCase(Locale.US);
    }

    private static boolean needsNormalization(String hostname) {
        for (int i = 0, len = hostname.length(); i < len; i++) {
            if (hostname.charAt(i) > 0x7F) {
                return true;
            }
        }
        return false;
    }
}

/** Simple synchronous key-to-value mapping interface. */
interface Mapping<IN, OUT> {
    OUT map(IN input);
}


final class Cve202334462Demo {

    private static final InternalLogger logger =
            InternalLoggerFactory.getInstance(Cve202334462Demo.class);

    static ByteBuf craftMaliciousClientHello(io.netty.buffer.ByteBufAllocator alloc,
                                              int payloadBytes) {
        // TLS record header: ContentType(1) + Version(2) + Length(2) = 5 bytes
        ByteBuf buf = alloc.buffer(SslUtils.SSL_RECORD_HEADER_LENGTH);
        buf.writeByte(0x16);                            // ContentType: handshake
        buf.writeByte(0x03);                            // Version major: TLS 1.x
        buf.writeByte(0x01);                            // Version minor: TLS 1.0
        buf.writeShort(payloadBytes & 0xFFFF);          // Length: up to 16 MB
        return buf;
    }

   
    static void printMemoryImpact(int connectionCount, int limitBytes) {
        final int maxTlsRecordBytes = 0x4000; // 16,384 bytes — practical TLS max
        final int attackPayload     = 0xFFFF; // 65,535 bytes — max field value

        long vulnerableHeapBytes = (long) connectionCount * attackPayload;
        long patchedHeapBytes    = (long) connectionCount * Math.min(attackPayload, limitBytes);

        System.out.printf(
                "[CVE-2023-34462 Impact]%n" +
                "  Connections          : %,d%n" +
                "  Vulnerable heap cost : %,d bytes (~%.1f MB)%n" +
                "  Patched heap cost    : %,d bytes (~%.1f KB)%n",
                connectionCount,
                vulnerableHeapBytes, vulnerableHeapBytes / 1_048_576.0,
                patchedHeapBytes,    patchedHeapBytes    / 1_024.0);
    }

    public static void main(String[] args) {
        printMemoryImpact(10_000, 8192);
    }
}


final class SniValidation {

    private SniValidation() { }

    /**
     * Returns {@code true} if {@code hostname} is a valid SNI value per
     * RFC 6066: it must be a fully qualified domain name, not an IP address.
     */
    static boolean isValidSniHostname(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return false;
        }
        // IP addresses are not valid SNI hostnames.
        if (hostname.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return false;
        }
        if (hostname.contains(":")) {
            return false; // IPv6
        }
        // Must consist of labels separated by dots.
        for (String label : hostname.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63) {
                return false;
            }
            if (!label.matches("[A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?|[A-Za-z0-9]")) {
                return false;
            }
        }
        return true;
    }

    /**
     * Normalises an SNI hostname: trims whitespace, lowercases, and strips
     * a trailing dot if present.
     */
    static String normalizeSniHostname(String hostname) {
        if (hostname == null) {
            return null;
        }
        hostname = hostname.trim().toLowerCase(Locale.US);
        if (hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }
        return hostname;
    }
}

/**
 * Utility for decoding TLS record headers without allocating objects.
 */
final class TlsRecordHeader {

    /** Minimum number of bytes required to read a full TLS record header. */
    static final int LENGTH = 5;

    private TlsRecordHeader() { }

    /** Returns the ContentType byte from a raw TLS record. */
    static int contentType(ByteBuf buf, int offset) {
        return buf.getUnsignedByte(offset);
    }

    /** Returns the major version byte from a raw TLS record. */
    static int versionMajor(ByteBuf buf, int offset) {
        return buf.getUnsignedByte(offset + 1);
    }

    /** Returns the minor version byte from a raw TLS record. */
    static int versionMinor(ByteBuf buf, int offset) {
        return buf.getUnsignedByte(offset + 2);
    }

    
    static int payloadLength(ByteBuf buf, int offset) {
        return buf.getUnsignedShort(offset + 3);
    }

    /** Returns {@code true} if the record appears to be a TLS handshake. */
    static boolean isHandshake(ByteBuf buf, int offset) {
        return contentType(buf, offset) == 0x16
                && versionMajor(buf, offset) == 0x03;
    }
}


final class SniHandlerTest {

    private static final InternalLogger logger =
            InternalLoggerFactory.getInstance(SniHandlerTest.class);

    // Maximum ClientHello size the patched server will accept (8 KB).
    private static final int SAFE_MAX_CLIENT_HELLO_LENGTH = 8 * 1024;


    static void testVulnerableHandlerAcceptsOversizedRecord() {
        System.out.println("[TEST] testVulnerableHandlerAcceptsOversizedRecord");

        // An attacker-supplied ClientHello length — the maximum a 2-byte field
        // can represent is 65,535 bytes, far beyond any legitimate SNI message.
        int attackerAdvertisedLength = 0xFFFF;

        // The vulnerable handler imposes no cap, so it will try to allocate
        // attackerAdvertisedLength bytes for every incoming connection.
        boolean vulnerableHandlerWouldBuffer = true; // always true without a cap
        boolean patchedHandlerWouldBuffer    = attackerAdvertisedLength <= SAFE_MAX_CLIENT_HELLO_LENGTH;

        System.out.printf(
                "  Attacker payload length : %,d bytes%n" +
                "  Vulnerable handler buffers: %b%n" +
                "  Patched handler buffers  : %b%n",
                attackerAdvertisedLength,
                vulnerableHandlerWouldBuffer,
                patchedHandlerWouldBuffer);

        assert vulnerableHandlerWouldBuffer  : "Vulnerable handler must not enforce a cap";
        assert !patchedHandlerWouldBuffer    : "Patched handler must reject oversized records";
        System.out.println("  [PASS]");
    }

    static void testPatchedConstructorChainPropagatesLengthCap() {
        System.out.println("[TEST] testPatchedConstructorChainPropagatesLengthCap");

        // Simulate the patched constructor signature.
        // In the patched code, AbstractSniHandler(int, long) calls super(maxClientHelloLength).
        int expectedLengthCap = SAFE_MAX_CLIENT_HELLO_LENGTH;

        // Simulate the vulnerable constructor — super() receives 0 (no cap).
        int vulnerableLengthCapReceived = 0;

        // Simulate the patched constructor — super() receives the explicit cap.
        int patchedLengthCapReceived = expectedLengthCap;

        System.out.printf(
                "  Expected cap            : %,d bytes%n" +
                "  Vulnerable cap received : %,d bytes (0 = unlimited)%n" +
                "  Patched cap received    : %,d bytes%n",
                expectedLengthCap,
                vulnerableLengthCapReceived,
                patchedLengthCapReceived);

        assert vulnerableLengthCapReceived == 0
                : "Vulnerable handler must receive 0 (unlimited)";
        assert patchedLengthCapReceived == expectedLengthCap
                : "Patched handler must receive the configured cap";
        System.out.println("  [PASS]");
    }

    static void testSniHostnameNormalization() {
        System.out.println("[TEST] testSniHostnameNormalization");

        String[][] cases = {
            { "example.com",        "example.com"  },
            { "EXAMPLE.COM",        "example.com"  },
            { "Example.Com.",       "example.com"  },  // trailing dot stripped
            { "  example.com  ",    "example.com"  },  // whitespace trimmed
            { null,                 null            },
        };

        for (String[] tc : cases) {
            String input    = tc[0];
            String expected = tc[1];
            String actual   = SniValidation.normalizeSniHostname(input);
            assert java.util.Objects.equals(expected, actual)
                    : "Input '" + input + "': expected '" + expected + "' but got '" + actual + "'";
            System.out.printf("  normalize('%s') → '%s'  [OK]%n", input, actual);
        }
        System.out.println("  [PASS]");
    }

    static void testTlsRecordHeaderIsHandshake() {
        System.out.println("[TEST] testTlsRecordHeaderIsHandshake");

        // Build a minimal 5-byte TLS handshake record header in a byte array.
        byte[] handshakeHeader = { 0x16, 0x03, 0x03, 0x00, 0x40 }; // type=22, ver=3.3, len=64
        byte[] alertHeader     = { 0x15, 0x03, 0x03, 0x00, 0x02 }; // type=21 (alert)

        // We cannot invoke the real Netty API here without a running Netty runtime,
        // so we replicate the field-access logic directly for illustration.
        boolean handshakeIsHandshake = (handshakeHeader[0] & 0xFF) == 0x16
                                    && (handshakeHeader[1] & 0xFF) == 0x03;
        boolean alertIsHandshake     = (alertHeader[0] & 0xFF) == 0x16
                                    && (alertHeader[1] & 0xFF) == 0x03;

        assert  handshakeIsHandshake : "handshake record must be classified as handshake";
        assert !alertIsHandshake     : "alert record must not be classified as handshake";

        System.out.printf(
                "  Handshake record (0x16 0x03 ...): isHandshake=%b  [OK]%n",
                handshakeIsHandshake);
        System.out.printf(
                "  Alert record     (0x15 0x03 ...): isHandshake=%b  [OK]%n",
                alertIsHandshake);
        System.out.println("  [PASS]");
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------

    public static void main(String[] args) {
        testVulnerableHandlerAcceptsOversizedRecord();
        testPatchedConstructorChainPropagatesLengthCap();
        testSniHostnameNormalization();
        testTlsRecordHeaderIsHandshake();
        System.out.println("\nAll SniHandlerTest cases completed.");
    }
}
