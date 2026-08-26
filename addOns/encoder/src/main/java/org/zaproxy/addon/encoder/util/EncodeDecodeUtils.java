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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/** Encoding and decoding helpers for the Encoder add-on's in-place operations. */
public final class EncodeDecodeUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static final String UNRESERVED =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
    private static final String URI_KEEP = UNRESERVED + "!'()*;,/?:@&=+$#";
    private static final String URI_COMPONENT_KEEP = UNRESERVED + "!'()*";

    private EncodeDecodeUtils() {}

    /* ---------------- Encode ---------------- */

    public static String encodeBase64(String text) {
        return Base64.getEncoder().encodeToString(bytes(text));
    }

    public static String encodeBase64Url(String text) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(text));
    }

    public static String encodeUrl(String text) {
        return percentEncode(text, UNRESERVED);
    }

    public static String encodeFullUrl(String text) {
        return percentEncode(text, "");
    }

    public static String encodeAsciiHex(String text) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes(text)) {
            sb.append(HEX[(b >> 4) & 0xf]).append(HEX[b & 0xf]);
        }
        return sb.toString();
    }

    public static String encodeHtml(String text) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&#39;");
                    break;
                default:
                    if (c >= 0x20 && c < 0x7f) {
                        sb.append(c);
                    } else {
                        sb.append("&#").append((int) c).append(';');
                    }
            }
        }
        return sb.toString();
    }

    public static String encodeFullHtml(String text) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            sb.append("&#").append((int) text.charAt(i)).append(';');
        }
        return sb.toString();
    }

    public static String encodeUri(String text) {
        return percentEncode(text, URI_KEEP);
    }

    public static String encodeUriComponent(String text) {
        return percentEncode(text, URI_COMPONENT_KEEP);
    }

    /* ---------------- Decode ---------------- */

    public static String decodeBase64(String text) {
        String cleaned = text.replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    public static String decodeBase64Url(String text) {
        String cleaned = text.replaceAll("\\s+", "");
        byte[] decoded = Base64.getUrlDecoder().decode(cleaned);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    public static String decodeUrl(String text) {
        return percentDecode(text, true);
    }

    public static String decodeFullUrl(String text) {
        return percentDecode(text, false);
    }

    public static String decodeAsciiHex(String text) {
        String cleaned = text.replaceAll("\\s+", "").replaceAll("(?i)0x", "");
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string has odd length: " + cleaned.length());
        }
        byte[] out = new byte[cleaned.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(cleaned.charAt(2 * i), 16);
            int lo = Character.digit(cleaned.charAt(2 * i + 1), 16);
            if (hi < 0) {
                throw new IllegalArgumentException("Invalid hex character at index " + (2 * i));
            }
            if (lo < 0) {
                throw new IllegalArgumentException(
                        "Invalid hex character at index " + (2 * i + 1));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    public static String decodeHtml(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == '&') {
                int semi = text.indexOf(';', i);
                if (semi > i && semi - i <= 32) {
                    String entity = text.substring(i + 1, semi);
                    Integer codePoint = resolveEntity(entity);
                    if (codePoint != null) {
                        sb.appendCodePoint(codePoint);
                        i = semi + 1;
                        continue;
                    }
                }
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    public static String decodeUri(String text) {
        return percentDecode(text, false);
    }

    public static String decodeUriComponent(String text) {
        return percentDecode(text, false);
    }

    /* ---------------- Internals ---------------- */

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String percentEncode(String text, String keep) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes(text)) {
            int v = b & 0xff;
            if (keep.indexOf((char) v) >= 0) {
                sb.append((char) v);
            } else {
                sb.append('%').append(HEX[(v >> 4) & 0xf]).append(HEX[v & 0xf]);
            }
        }
        return sb.toString();
    }

    private static String percentDecode(String text, boolean plusAsSpace) {
        byte[] out = new byte[text.length()];
        int oi = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length()) {
                int hi = Character.digit(text.charAt(i + 1), 16);
                int lo = Character.digit(text.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out[oi++] = (byte) ((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            if (c == '+' && plusAsSpace) {
                out[oi++] = ' ';
            } else {
                byte[] encoded = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                System.arraycopy(encoded, 0, out, oi, encoded.length);
                oi += encoded.length;
            }
        }
        return new String(out, 0, oi, StandardCharsets.UTF_8);
    }

    private static Integer resolveEntity(String entity) {
        if (entity.startsWith("#x") || entity.startsWith("#X")) {
            try {
                return Integer.parseInt(entity.substring(2), 16);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (entity.startsWith("#")) {
            try {
                return Integer.parseInt(entity.substring(1));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return NAMED_ENTITIES.get(entity);
    }

    private static final Map<String, Integer> NAMED_ENTITIES = buildNamedEntities();

    private static Map<String, Integer> buildNamedEntities() {
        Map<String, Integer> m = new HashMap<>();
        m.put("quot", 34);
        m.put("amp", 38);
        m.put("apos", 39);
        m.put("lt", 60);
        m.put("gt", 62);
        m.put("nbsp", 160);
        m.put("iexcl", 161);
        m.put("cent", 162);
        m.put("pound", 163);
        m.put("curren", 164);
        m.put("yen", 165);
        m.put("brvbar", 166);
        m.put("sect", 167);
        m.put("uml", 168);
        m.put("copy", 169);
        m.put("ordf", 170);
        m.put("laquo", 171);
        m.put("not", 172);
        m.put("shy", 173);
        m.put("reg", 174);
        m.put("macr", 175);
        m.put("deg", 176);
        m.put("plusmn", 177);
        m.put("sup2", 178);
        m.put("sup3", 179);
        m.put("acute", 180);
        m.put("micro", 181);
        m.put("para", 182);
        m.put("middot", 183);
        m.put("cedil", 184);
        m.put("sup1", 185);
        m.put("ordm", 186);
        m.put("raquo", 187);
        m.put("frac14", 188);
        m.put("frac12", 189);
        m.put("frac34", 190);
        m.put("iquest", 191);
        m.put("Agrave", 192);
        m.put("Aacute", 193);
        m.put("Acirc", 194);
        m.put("Atilde", 195);
        m.put("Auml", 196);
        m.put("Aring", 197);
        m.put("AElig", 198);
        m.put("Ccedil", 199);
        m.put("Egrave", 200);
        m.put("Eacute", 201);
        m.put("Ecirc", 202);
        m.put("Euml", 203);
        m.put("Igrave", 204);
        m.put("Iacute", 205);
        m.put("Icirc", 206);
        m.put("Iuml", 207);
        m.put("ETH", 208);
        m.put("Ntilde", 209);
        m.put("Ograve", 210);
        m.put("Oacute", 211);
        m.put("Ocirc", 212);
        m.put("Otilde", 213);
        m.put("Ouml", 214);
        m.put("times", 215);
        m.put("Oslash", 216);
        m.put("Ugrave", 217);
        m.put("Uacute", 218);
        m.put("Ucirc", 219);
        m.put("Uuml", 220);
        m.put("Yacute", 221);
        m.put("THORN", 222);
        m.put("szlig", 223);
        m.put("agrave", 224);
        m.put("aacute", 225);
        m.put("acirc", 226);
        m.put("atilde", 227);
        m.put("auml", 228);
        m.put("aring", 229);
        m.put("aelig", 230);
        m.put("ccedil", 231);
        m.put("egrave", 232);
        m.put("eacute", 233);
        m.put("ecirc", 234);
        m.put("euml", 235);
        m.put("igrave", 236);
        m.put("iacute", 237);
        m.put("icirc", 238);
        m.put("iuml", 239);
        m.put("eth", 240);
        m.put("ntilde", 241);
        m.put("ograve", 242);
        m.put("oacute", 243);
        m.put("ocirc", 244);
        m.put("otilde", 245);
        m.put("ouml", 246);
        m.put("divide", 247);
        m.put("oslash", 248);
        m.put("ugrave", 249);
        m.put("uacute", 250);
        m.put("ucirc", 251);
        m.put("uuml", 252);
        m.put("yacute", 253);
        m.put("thorn", 254);
        m.put("yuml", 255);
        m.put("OElig", 338);
        m.put("oelig", 339);
        m.put("Scaron", 352);
        m.put("scaron", 353);
        m.put("Yuml", 376);
        m.put("fnof", 402);
        m.put("circ", 710);
        m.put("tilde", 732);
        m.put("Alpha", 913);
        m.put("Beta", 914);
        m.put("Gamma", 915);
        m.put("Delta", 916);
        m.put("Epsilon", 917);
        m.put("Zeta", 918);
        m.put("Eta", 919);
        m.put("Theta", 920);
        m.put("Iota", 921);
        m.put("Kappa", 922);
        m.put("Lambda", 923);
        m.put("Mu", 924);
        m.put("Nu", 925);
        m.put("Xi", 926);
        m.put("Omicron", 927);
        m.put("Pi", 928);
        m.put("Rho", 929);
        m.put("Sigma", 931);
        m.put("Tau", 932);
        m.put("Upsilon", 933);
        m.put("Phi", 934);
        m.put("Chi", 935);
        m.put("Psi", 936);
        m.put("Omega", 937);
        m.put("alpha", 945);
        m.put("beta", 946);
        m.put("gamma", 947);
        m.put("delta", 948);
        m.put("epsilon", 949);
        m.put("zeta", 950);
        m.put("eta", 951);
        m.put("theta", 952);
        m.put("iota", 953);
        m.put("kappa", 954);
        m.put("lambda", 955);
        m.put("mu", 956);
        m.put("nu", 957);
        m.put("xi", 958);
        m.put("omicron", 959);
        m.put("pi", 960);
        m.put("rho", 961);
        m.put("sigmaf", 962);
        m.put("sigma", 963);
        m.put("tau", 964);
        m.put("upsilon", 965);
        m.put("phi", 966);
        m.put("chi", 967);
        m.put("psi", 968);
        m.put("omega", 969);
        m.put("thetasym", 977);
        m.put("upsih", 978);
        m.put("piv", 982);
        m.put("ensp", 8194);
        m.put("emsp", 8195);
        m.put("thinsp", 8201);
        m.put("zwnj", 8204);
        m.put("zwj", 8205);
        m.put("lrm", 8206);
        m.put("rlm", 8207);
        m.put("ndash", 8211);
        m.put("mdash", 8212);
        m.put("lsquo", 8216);
        m.put("rsquo", 8217);
        m.put("sbquo", 8218);
        m.put("ldquo", 8220);
        m.put("rdquo", 8221);
        m.put("bdquo", 8222);
        m.put("dagger", 8224);
        m.put("Dagger", 8225);
        m.put("bull", 8226);
        m.put("hellip", 8230);
        m.put("permil", 8240);
        m.put("prime", 8242);
        m.put("Prime", 8243);
        m.put("lsaquo", 8249);
        m.put("rsaquo", 8250);
        m.put("oline", 8254);
        m.put("frasl", 8260);
        m.put("euro", 8364);
        m.put("image", 8465);
        m.put("weierp", 8472);
        m.put("real", 8476);
        m.put("trade", 8482);
        m.put("alefsym", 8501);
        m.put("larr", 8592);
        m.put("uarr", 8593);
        m.put("rarr", 8594);
        m.put("darr", 8595);
        m.put("harr", 8596);
        m.put("crarr", 8629);
        m.put("lArr", 8656);
        m.put("uArr", 8657);
        m.put("rArr", 8658);
        m.put("dArr", 8659);
        m.put("hArr", 8660);
        m.put("forall", 8704);
        m.put("part", 8706);
        m.put("exist", 8707);
        m.put("empty", 8709);
        m.put("nabla", 8711);
        m.put("isin", 8712);
        m.put("notin", 8713);
        m.put("ni", 8715);
        m.put("prod", 8719);
        m.put("sum", 8721);
        m.put("minus", 8722);
        m.put("lowast", 8727);
        m.put("radic", 8730);
        m.put("prop", 8733);
        m.put("infin", 8734);
        m.put("ang", 8736);
        m.put("and", 8743);
        m.put("or", 8744);
        m.put("cap", 8745);
        m.put("cup", 8746);
        m.put("int", 8747);
        m.put("there4", 8756);
        m.put("sim", 8764);
        m.put("cong", 8773);
        m.put("asymp", 8776);
        m.put("ne", 8800);
        m.put("equiv", 8801);
        m.put("le", 8804);
        m.put("ge", 8805);
        m.put("sub", 8834);
        m.put("sup", 8835);
        m.put("nsub", 8836);
        m.put("sube", 8838);
        m.put("supe", 8839);
        m.put("oplus", 8853);
        m.put("otimes", 8855);
        m.put("perp", 8869);
        m.put("sdot", 8901);
        m.put("lceil", 8968);
        m.put("rceil", 8969);
        m.put("lfloor", 8970);
        m.put("rfloor", 8971);
        m.put("lang", 9001);
        m.put("rang", 9002);
        m.put("loz", 9674);
        m.put("spades", 9824);
        m.put("clubs", 9827);
        m.put("hearts", 9829);
        m.put("diams", 9830);
        return m;
    }
}
