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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Unicode confusables data (UTS #39, Unicode 17.0.0) for homoglyph testing.
 *
 * <p>Provides two conversion directions:
 *
 * <ul>
 *   <li>{@link #toAscii(String)} maps a glyph (e.g. Greek alpha) to its ASCII confusable
 *       equivalent;
 *   <li>{@link #toGlyph(String, String)} maps ASCII characters to confusable glyphs of a given
 *       category (script or style), e.g. {@code toGlyph("abc", "Greek")} returns
 *       {@code \u03b1\u03b2c}.
 * </ul>
 */
public final class Confusables {

    private static final String CATEGORY_OTHER = "Other";
    private static final String CATEGORY_UNKNOWN = "Unknown";

    private static final class Holder {
        static final Confusables INSTANCE = new Confusables(
                ConfusablesData.glyphToAscii(), ConfusablesData.asciiToGlyph());
    }

    private final Map<Integer, String> glyphToAscii;
    private final Map<Integer, Map<String, String>> asciiToGlyph;

    private Confusables(Map<Integer, String> glyphToAscii, Map<Integer, Map<String, String>> asciiToGlyph) {
        this.glyphToAscii = glyphToAscii;
        this.asciiToGlyph = asciiToGlyph;
    }

    public static Confusables getInstance() {
        return Holder.INSTANCE;
    }

    /** Converts each character to its confusable equivalent when the equivalent is pure ASCII. */
    public String toAscii(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        text.codePoints()
                .forEach(
                        cp -> {
                            String confusable = glyphToAscii.get(cp);
                            if (confusable != null) {
                                sb.append(confusable);
                            } else {
                                sb.appendCodePoint(cp);
                            }
                        });
        return sb.toString();
    }

    /**
     * Converts each character to a confusable glyph of the given category.
     *
     * <p>Characters without a confusable of the requested category are left unchanged.
     *
     * @param text the text to convert
     * @param category a category returned by {@link #categories()}, e.g. {@code "Greek"}
     * @return the converted text
     */
    public String toGlyph(String text, String category) {
        StringBuilder sb = new StringBuilder(text.length());
        text.codePoints()
                .forEach(
                        cp -> {
                            Map<String, String> byCategory = asciiToGlyph.get(cp);
                            String confusable =
                                    byCategory == null ? null : byCategory.get(category);
                            if (confusable != null) {
                                sb.append(confusable);
                            } else {
                                sb.appendCodePoint(cp);
                            }
                        });
        return sb.toString();
    }

    /**
     * Returns the sorted available glyph categories.
     *
     * <p>Only categories that provide a confusable for at least one printable ASCII character are
     * included.
     */
    public List<String> categories() {
        TreeSet<String> categories = new TreeSet<>();
        for (Map.Entry<Integer, Map<String, String>> entry : asciiToGlyph.entrySet()) {
            int targetCp = entry.getKey();
            if (targetCp >= 0x21 && targetCp <= 0x7e) {
                categories.addAll(entry.getValue().keySet());
            }
        }
        categories.remove(CATEGORY_OTHER);
        categories.remove(CATEGORY_UNKNOWN);
        return Collections.unmodifiableList(new ArrayList<>(categories));
    }
}
