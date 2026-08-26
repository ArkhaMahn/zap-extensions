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

import io.github.rctcwyvrn.blake3.Blake3;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Hashing helpers for the Encoder add-on's in-place operations. */
public final class HashUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HashUtils() {}

    /* ---------------- Simple digests ---------------- */

    public static String sha1(String text) {
        return jdkDigest("SHA-1", bytes(text));
    }

    public static String sha256(String text) {
        return jdkDigest("SHA-256", bytes(text));
    }

    public static String sha512(String text) {
        return jdkDigest("SHA-512", bytes(text));
    }

    public static String md5(String text) {
        return jdkDigest("MD5", bytes(text));
    }

    public static String sha3Keccak(String text) {
        return keccak(bytes(text));
    }

    public static String md4(String text) {
        byte[] data = bytes(text);
        byte[] out = new byte[16];
        MD4Digest digest = new MD4Digest();
        digest.update(data, 0, data.length);
        digest.doFinal(out, 0);
        return hex(out);
    }

    public static String blake2(String text) {
        byte[] out = new byte[32];
        Blake2bDigest digest = new Blake2bDigest(256);
        digest.update(bytes(text), 0, bytes(text).length);
        digest.doFinal(out, 0);
        return hex(out);
    }

    public static String blake3(String text) {
        Blake3 hasher = Blake3.newInstance();
        hasher.update(bytes(text));
        return hasher.hexdigest();
    }

    public static String whirlpool(String text) {
        byte[] out = new byte[64];
        WhirlpoolDigest digest = new WhirlpoolDigest();
        digest.update(bytes(text), 0, bytes(text).length);
        digest.doFinal(out, 0);
        return hex(out);
    }

    /* ---------------- Checksums / non-cryptographic ---------------- */

    public static String crc32(String text) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(bytes(text));
        return String.format("%08x", crc.getValue());
    }

    public static String murmur3(String text) {
        return String.format("%08x", murmur3_32(bytes(text), 0));
    }

    public static String fnv1a(String text) {
        long hash = 0xcbf29ce484222325L;
        for (byte b : bytes(text)) {
            hash ^= (b & 0xff);
            hash *= 0x100000001b3L;
        }
        return String.format("%016x", hash);
    }

    public static String sipHash(String text) {
        byte[] key = salt(text, 16);
        byte[] data = bytes(text);
        long k0 = leLong(key, 0);
        long k1 = leLong(key, 8);
        long[] v = {
            0x736f6d6570736575L ^ k0,
            0x646f72616e646f6dL ^ k1,
            0x6c7967656e657261L ^ k0,
            0x7465646279746573L ^ k1
        };

        int i = 0;
        while (i + 8 <= data.length) {
            long m = leLong(data, i);
            v[3] ^= m;
            sipRound(v);
            sipRound(v);
            v[0] ^= m;
            i += 8;
        }

        long b = (long) data.length << 56;
        int remaining = data.length - i;
        for (int t = 0; t < remaining; t++) {
            b |= (long) (data[i + t] & 0xff) << (8 * t);
        }
        v[3] ^= b;
        sipRound(v);
        sipRound(v);
        v[0] ^= b;

        v[2] ^= 0xff;
        sipRound(v);
        sipRound(v);
        sipRound(v);
        sipRound(v);

        return String.format("%016x", v[0] ^ v[1] ^ v[2] ^ v[3]);
    }

    /* ---------------- Salted / keyed hashes ---------------- */

    public static String bcrypt(String text) {
        byte[] salt = salt(text, 16);
        return OpenBSDBCrypt.generate(bytes(text), salt, 10);
    }

    public static String scrypt(String text) {
        byte[] salt = salt(text, 16);
        byte[] out = SCrypt.generate(bytes(text), salt, 16384, 8, 1, 32);
        return "$scrypt$ln=14,r=8,p=1$"
                + Base64.getEncoder().withoutPadding().encodeToString(salt)
                + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(out);
    }

    public static String argon2id(String text) {
        byte[] salt = salt(text, 16);
        Argon2Parameters params =
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withSalt(salt)
                        .withParallelism(1)
                        .withMemoryAsKB(19456)
                        .withIterations(2)
                        .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] out = new byte[32];
        generator.generateBytes(bytes(text), out);
        return "$argon2id$v=19$m=19456,t=2,p=1$"
                + Base64.getEncoder().withoutPadding().encodeToString(salt)
                + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(out);
    }

    public static String pbkdf2(String text) {
        byte[] salt = salt(text, 16);
        try {
            PBEKeySpec spec = new PBEKeySpec(text.toCharArray(), salt, 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return hex(factory.generateSecret(spec).getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("PBKDF2 not available", e);
        }
    }

    public static String phpass(String text) {
        final String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        int countLog2 = 9; // 512 iterations
        byte[] seed = sha256Bytes(text);
        StringBuilder saltBuilder = new StringBuilder(8);
        int s = 0;
        for (int i = 0; i < 8; i++) {
            s = (s << 6) | (seed[i] & 0x3f);
            saltBuilder.append(itoa64.charAt((s >>> 6) & 0x3f));
        }
        String saltStr = saltBuilder.substring(0, 8);
        byte[] hash = md5Bytes((saltStr + text).getBytes(StandardCharsets.UTF_8));
        int count = 1 << countLog2;
        for (int i = 0; i < count; i++) {
            hash = md5Bytes(concat(hash, bytes(text)));
        }
        return "$P$"
                + itoa64.charAt(countLog2)
                + saltStr
                + encode64Phpass(hash, 16);
    }

    /* ---------------- Internals ---------------- */

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String jdkDigest(String algorithm, byte[] data) {
        try {
            return hex(MessageDigest.getInstance(algorithm).digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Digest not available: " + algorithm, e);
        }
    }

    private static byte[] sha256Bytes(String text) {
        return sha256Digest(text);
    }

    private static byte[] sha256Digest(String text) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes(text));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] md5Bytes(byte[] data) {
        try {
            return MessageDigest.getInstance("MD5").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String keccak(byte[] data) {
        byte[] out = new byte[32];
        KeccakDigest digest = new KeccakDigest(256);
        digest.update(data, 0, data.length);
        digest.doFinal(out, 0);
        return hex(out);
    }

    private static byte[] salt(String text, int length) {
        byte[] digest = sha256Digest(text);
        byte[] salt = new byte[length];
        for (int i = 0; i < length; i++) {
            salt[i] = digest[i % digest.length];
        }
        return salt;
    }

    private static String encode64Phpass(byte[] input, int count) {
        final String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        StringBuilder output = new StringBuilder();
        int i = 0;
        do {
            int value = input[i++] & 0xff;
            output.append(itoa64.charAt(value & 0x3f));
            if (i < count) {
                value |= (input[i] & 0xff) << 8;
            }
            output.append(itoa64.charAt((value >>> 6) & 0x3f));
            if (i++ >= count) {
                break;
            }
            if (i < count) {
                value |= (input[i] & 0xff) << 16;
            }
            output.append(itoa64.charAt((value >>> 12) & 0x3f));
            if (i++ >= count) {
                break;
            }
            output.append(itoa64.charAt((value >>> 18) & 0x3f));
        } while (i < count);
        return output.toString();
    }

    private static void sipRound(long[] v) {
        v[0] += v[1];
        v[1] = Long.rotateLeft(v[1], 13);
        v[1] ^= v[0];
        v[0] = Long.rotateLeft(v[0], 32);
        v[2] += v[3];
        v[3] = Long.rotateLeft(v[3], 16);
        v[3] ^= v[2];
        v[0] += v[3];
        v[3] = Long.rotateLeft(v[3], 21);
        v[3] ^= v[0];
        v[2] += v[1];
        v[1] = Long.rotateLeft(v[1], 17);
        v[1] ^= v[2];
        v[2] = Long.rotateLeft(v[2], 32);
    }

    private static long leLong(byte[] data, int offset) {
        long value = 0;
        for (int i = 7; i >= 0; i--) {
            value = (value << 8) | (data[offset + i] & 0xff);
        }
        return value;
    }

    @SuppressWarnings("fallthrough")
    private static int murmur3_32(byte[] data, int seed) {
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;
        int h1 = seed;
        int len = data.length;
        int nblocks = len / 4;
        for (int i = 0; i < nblocks; i++) {
            int k1 =
                    data[4 * i] & 0xff
                            | (data[4 * i + 1] & 0xff) << 8
                            | (data[4 * i + 2] & 0xff) << 16
                            | (data[4 * i + 3] & 0xff) << 24;
            k1 = Integer.rotateLeft(k1 * c1, 15) * c2;
            h1 ^= k1;
            h1 = Integer.rotateLeft(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }
        int k1 = 0;
        int tail = nblocks * 4;
        switch (len & 3) {
            case 3:
                k1 ^= (data[tail + 2] & 0xff) << 16;
                // fall through
            case 2:
                k1 ^= (data[tail + 1] & 0xff) << 8;
                // fall through
            case 1:
                k1 ^= data[tail] & 0xff;
                k1 = Integer.rotateLeft(k1 * c1, 15) * c2;
                h1 ^= k1;
        }
        h1 ^= len;
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;
        return h1;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX[(b >> 4) & 0xf]).append(HEX[b & 0xf]);
        }
        return sb.toString();
    }
}
