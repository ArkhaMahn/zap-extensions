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
package org.zaproxy.addon.encoder;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.swing.text.JTextComponent;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.popup.EncoderOperationMenuItem;
import org.zaproxy.addon.encoder.popup.EncoderSubMenu;
import org.zaproxy.addon.encoder.util.Confusables;
import org.zaproxy.addon.encoder.util.ConvertUtils;
import org.zaproxy.addon.encoder.util.EncodeDecodeUtils;
import org.zaproxy.addon.encoder.util.HashUtils;

/** Builds the in-place Encode, Decode, Hash, and Convert submenus for the right-click menu. */
final class EncoderPopupSubMenus {

    private EncoderPopupSubMenus() {}

    static String msg(String key) {
        return Constant.messages.getString(key);
    }

    static EncoderSubMenu encodeSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<EncoderOperationMenuItem> items = new ArrayList<>();
        items.add(item("encoder.operation.encode.base64", EncodeDecodeUtils::encodeBase64, invokerSupplier));
        items.add(item("encoder.operation.encode.base64url", EncodeDecodeUtils::encodeBase64Url, invokerSupplier));
        items.add(item("encoder.operation.encode.url", EncodeDecodeUtils::encodeUrl, invokerSupplier));
        items.add(item("encoder.operation.encode.fullurl", EncodeDecodeUtils::encodeFullUrl, invokerSupplier));
        items.add(item("encoder.operation.encode.asciihex", EncodeDecodeUtils::encodeAsciiHex, invokerSupplier));
        items.add(item("encoder.operation.encode.html", EncodeDecodeUtils::encodeHtml, invokerSupplier));
        items.add(item("encoder.operation.encode.fullhtml", EncodeDecodeUtils::encodeFullHtml, invokerSupplier));
        items.add(item("encoder.operation.encode.encodeuri", EncodeDecodeUtils::encodeUri, invokerSupplier));
        items.add(item("encoder.operation.encode.encodeuricomponent", EncodeDecodeUtils::encodeUriComponent, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.popup.encode"), items);
    }

    static EncoderSubMenu decodeSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<EncoderOperationMenuItem> items = new ArrayList<>();
        items.add(item("encoder.operation.decode.base64", EncodeDecodeUtils::decodeBase64, invokerSupplier));
        items.add(item("encoder.operation.decode.base64url", EncodeDecodeUtils::decodeBase64Url, invokerSupplier));
        items.add(item("encoder.operation.decode.url", EncodeDecodeUtils::decodeUrl, invokerSupplier));
        items.add(item("encoder.operation.decode.fullurl", EncodeDecodeUtils::decodeFullUrl, invokerSupplier));
        items.add(item("encoder.operation.decode.asciihex", EncodeDecodeUtils::decodeAsciiHex, invokerSupplier));
        items.add(item("encoder.operation.decode.html", EncodeDecodeUtils::decodeHtml, invokerSupplier));
        items.add(item("encoder.operation.decode.fullhtml", EncodeDecodeUtils::decodeHtml, invokerSupplier));
        items.add(item("encoder.operation.decode.decodeuri", EncodeDecodeUtils::decodeUri, invokerSupplier));
        items.add(item("encoder.operation.decode.decodeuricomponent", EncodeDecodeUtils::decodeUriComponent, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.popup.decode"), items);
    }

    static EncoderSubMenu hashSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<Component> items = new ArrayList<>();
        items.add(shaSubMenu(invokerSupplier));
        items.add(mdSubMenu(invokerSupplier));
        items.add(item("encoder.operation.hash.crc32", HashUtils::crc32, invokerSupplier));
        items.add(item("encoder.operation.hash.murmurhash3", HashUtils::murmur3, invokerSupplier));
        items.add(item("encoder.operation.hash.argon2id", HashUtils::argon2id, invokerSupplier));
        items.add(item("encoder.operation.hash.bcrypt", HashUtils::bcrypt, invokerSupplier));
        items.add(item("encoder.operation.hash.scrypt", HashUtils::scrypt, invokerSupplier));
        items.add(item("encoder.operation.hash.pbkdf2", HashUtils::pbkdf2, invokerSupplier));
        items.add(item("encoder.operation.hash.phpass", HashUtils::phpass, invokerSupplier));
        items.add(blakeSubMenu(invokerSupplier));
        items.add(item("encoder.operation.hash.whirlpool", HashUtils::whirlpool, invokerSupplier));
        items.add(item("encoder.operation.hash.siphash", HashUtils::sipHash, invokerSupplier));
        items.add(item("encoder.operation.hash.fnv1a", HashUtils::fnv1a, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.popup.hash"), items);
    }

    private static EncoderSubMenu shaSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<Component> shaItems = new ArrayList<>();
        shaItems.add(item("encoder.operation.hash.sha1", HashUtils::sha1, invokerSupplier));
        shaItems.add(item("encoder.operation.hash.sha3", HashUtils::sha3Keccak, invokerSupplier));
        shaItems.add(item("encoder.operation.hash.sha256", HashUtils::sha256, invokerSupplier));
        shaItems.add(item("encoder.operation.hash.sha512", HashUtils::sha512, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.hash.sha"), shaItems);
    }

    private static EncoderSubMenu mdSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<Component> mdItems = new ArrayList<>();
        mdItems.add(item("encoder.operation.hash.md4", HashUtils::md4, invokerSupplier));
        mdItems.add(item("encoder.operation.hash.md5", HashUtils::md5, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.hash.md"), mdItems);
    }

    private static EncoderSubMenu blakeSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<EncoderOperationMenuItem> blakeItems = new ArrayList<>();
        blakeItems.add(item("encoder.operation.hash.blake2", HashUtils::blake2, invokerSupplier));
        blakeItems.add(item("encoder.operation.hash.blake3", HashUtils::blake3, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.hash.blake"), blakeItems);
    }

    static EncoderSubMenu convertSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<Component> items = new ArrayList<>();
        items.add(item("encoder.operation.convert.unicode", ConvertUtils::unicode, invokerSupplier));
        items.add(utfSubMenu(invokerSupplier));
        items.add(item("encoder.operation.convert.ascii", Confusables.getInstance()::toAscii, invokerSupplier));
        items.add(confusablesSubMenu(invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.popup.convert"), items);
    }

    private static EncoderSubMenu utfSubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<Component> utfItems = new ArrayList<>();
        utfItems.add(illegalUtf8SubMenu(invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf7", ConvertUtils::utf7, invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf8", ConvertUtils::utf8, invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf16le", ConvertUtils::utf16Le, invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf16be", ConvertUtils::utf16Be, invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf32", ConvertUtils::utf32, invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf32le", ConvertUtils::utf32Le, invokerSupplier));
        utfItems.add(item("encoder.operation.convert.utf32be", ConvertUtils::utf32Be, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.convert.utf"), utfItems);
    }

    private static EncoderSubMenu illegalUtf8SubMenu(Supplier<JTextComponent> invokerSupplier) {
        List<Component> items = new ArrayList<>();
        items.add(item("encoder.operation.convert.illegalutf8_2", ConvertUtils::illegalUtf82Bytes, invokerSupplier));
        items.add(item("encoder.operation.convert.illegalutf8_3", ConvertUtils::illegalUtf83Bytes, invokerSupplier));
        items.add(item("encoder.operation.convert.illegalutf8_4", ConvertUtils::illegalUtf84Bytes, invokerSupplier));
        return new EncoderSubMenu(msg("encoder.operation.convert.illegalutf8"), items);
    }

    private static EncoderSubMenu confusablesSubMenu(Supplier<JTextComponent> invokerSupplier) {
        Confusables confusables = Confusables.getInstance();
        List<EncoderOperationMenuItem> glyphItems = new ArrayList<>();
        for (String category : confusables.categories()) {
            glyphItems.add(
                    new EncoderOperationMenuItem(
                            category, text -> confusables.toGlyph(text, category), invokerSupplier));
        }
        return new EncoderSubMenu(msg("encoder.operation.convert.confusables"), glyphItems);
    }

    private static EncoderOperationMenuItem item(String key, Function<String, String> op, Supplier<JTextComponent> invokerSupplier) {
        return new EncoderOperationMenuItem(msg(key), op, invokerSupplier);
    }
}
