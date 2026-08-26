/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.encoder.util;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Character-set and text conversion helpers for the Encoder add-on. */
public final class ConvertUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private ConvertUtils() {}

    /** Re-decodes the text (taken as ISO-8859-1 bytes) as strict UTF-8, fixing illegal sequences. */
    public static String illegalUtf8(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.ISO_8859_1);
        CharsetDecoder decoder =
                StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPLACE)
                        .onUnmappableCharacter(CodingErrorAction.REPLACE);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Could not decode as UTF-8", e);
        }
    }

    /**
     * Percent-encodes each character as an overlong 2-byte UTF-8 sequence, as done by the ZAP
     * "Encode / Decode / Hash" add-on.
     */
    public static String illegalUtf82Bytes(String text) {
        return overlongUtf8(text, 2);
    }

    /**
     * Percent-encodes each character as an overlong 3-byte UTF-8 sequence, as done by the ZAP
     * "Encode / Decode / Hash" add-on.
     */
    public static String illegalUtf83Bytes(String text) {
        return overlongUtf8(text, 3);
    }

    /**
     * Percent-encodes each character as an overlong 4-byte UTF-8 sequence, as done by the ZAP
     * "Encode / Decode / Hash" add-on.
     */
    public static String illegalUtf84Bytes(String text) {
        return overlongUtf8(text, 4);
    }

    /**
     * Encodes each (low 7-bit) character as an overlong UTF-8 sequence of the given byte length,
     * with each byte percent-encoded. Overlong encodings violate RFC 3629 but are used to probe
     * WAF/decoder handling of malformed UTF-8.
     */
    private static String overlongUtf8(String text, int bytes) {
        StringBuilder sb = new StringBuilder(text.length() * bytes * 3);
        for (char c : text.toCharArray()) {
            int v = c & 0x7f;
            if (bytes == 4) {
                sb.append("%f0%80");
                sb.append(pctHex(0x80 | (v >> 6)));
                sb.append(pctHex(0x80 | (v & 0x3f)));
            } else if (bytes == 3) {
                sb.append("%e0");
                sb.append(pctHex(0x80 | (v >> 6)));
                sb.append(pctHex(0x80 | (v & 0x3f)));
            } else {
                sb.append(pctHex(0xc0 | (v >> 6)));
                sb.append(pctHex(0x80 | (v & 0x3f)));
            }
        }
        return sb.toString();
    }

    private static String pctHex(int b) {
        return String.format("%%%02x", b & 0xff);
    }

    /** Shows each code point of the text as a Unicode code point (e.g. {@code U+0041}). */
    public static String unicode(String text) {
        StringBuilder sb = new StringBuilder();
        text.codePoints()
                .forEach(cp -> sb.append(String.format("U+%04X ", cp)));
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }

    /** Encodes the text using UTF-7 (RFC 2152) and returns the encoded string. */
    public static String utf7(String text) {
        StringBuilder sb = new StringBuilder();
        StringBuilder run = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '+') {
                flushUtf7Run(sb, run);
                sb.append("+-");
            } else if (isDirectUtf7(c)) {
                flushUtf7Run(sb, run);
                sb.append(c);
            } else {
                run.append(c);
            }
        }
        flushUtf7Run(sb, run);
        return sb.toString();
    }

    private static void flushUtf7Run(StringBuilder sb, StringBuilder run) {
        if (run.length() == 0) {
            return;
        }
        byte[] utf16be = run.toString().getBytes(StandardCharsets.UTF_16BE);
        String b64 = Base64.getEncoder().encodeToString(utf16be);
        while (b64.endsWith("=")) {
            b64 = b64.substring(0, b64.length() - 1);
        }
        sb.append('+').append(b64).append('-');
        run.setLength(0);
    }

    public static String utf8(String text) {
        return toHex(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String utf16Le(String text) {
        return toHex(text.getBytes(StandardCharsets.UTF_16LE));
    }

    public static String utf16Be(String text) {
        return toHex(text.getBytes(StandardCharsets.UTF_16BE));
    }

    public static String utf32Le(String text) {
        return toHex(text.getBytes(Charset.forName("UTF-32LE")));
    }

    public static String utf32Be(String text) {
        return toHex(text.getBytes(Charset.forName("UTF-32BE")));
    }

    public static String utf32(String text) {
        return toHex(text.getBytes(Charset.forName("UTF-32")));
    }

    private static boolean isDirectUtf7(char c) {
        if (c == '\\' || c == '+') {
            return false;
        }
        return (c >= 0x20 && c <= 0x7e)
                || (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '\''
                || c == '('
                || c == ')'
                || c == ','
                || c == '-'
                || c == '.'
                || c == '/'
                || c == ':'
                || c == '?';
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX[(b >> 4) & 0xf]).append(HEX[b & 0xf]);
        }
        return sb.toString();
    }
}
