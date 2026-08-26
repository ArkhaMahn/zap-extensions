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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.swing.text.JTextComponent;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.addon.encoder.popup.EncoderOperationMenuItem;
import org.zaproxy.addon.encoder.popup.EncoderSubMenu;
import org.zaproxy.addon.encoder.util.Confusables;
import org.zaproxy.addon.encoder.util.ConvertUtils;
import org.zaproxy.addon.encoder.util.EncodeDecodeUtils;
import org.zaproxy.addon.encoder.util.HashUtils;
import org.zaproxy.zap.extension.ExtensionPopupMenu;

/**
 * The "Encode/Decode/Hash..." right-click menu. Hovering shows the in-place Encode, Decode, Hash,
 * and Convert submenus. Clicking the menu opens the Encode/Decode/Hash dialog.
 */
@SuppressWarnings("serial")
public class PopupEncoderMenu extends ExtensionPopupMenu {

    private static final long serialVersionUID = 1L;
    private volatile JTextComponent lastInvoker = null;
    private final Supplier<JTextComponent> invokerSupplier = () -> lastInvoker;

    public PopupEncoderMenu(Runnable dialogAction) {
        super(Constant.messages.getString("encoder.tools.menu.encdec"));
        setWeight(MenuWeights.MENU_ENCODE_WEIGHT);

        addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        dialogAction.run();
                    }
                });

        add(new EncoderSubMenu(msg("encoder.operation.popup.encode"), encodeItems()));
        add(new EncoderSubMenu(msg("encoder.operation.popup.decode"), decodeItems()));
        add(new EncoderSubMenu(msg("encoder.operation.popup.hash"), hashItems()));
        add(new EncoderSubMenu(msg("encoder.operation.popup.convert"), convertItems()));
    }

    private static String msg(String key) {
        return Constant.messages.getString(key);
    }

    /**
     * @return Returns the lastInvoker.
     */
    public JTextComponent getLastInvoker() {
        return lastInvoker;
    }

    /**
     * @param lastInvoker The lastInvoker to set.
     */
    public void setLastInvoker(JTextComponent lastInvoker) {
        this.lastInvoker = lastInvoker;
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTextComponent
                && !EncodeDecodeDialog.isInvokerFromEncodeDecode(invoker)) {
            JTextComponent txt = (JTextComponent) invoker;
            String sel = txt.getSelectedText();
            this.setEnabled(!(sel == null || sel.length() == 0));
            setLastInvoker((JTextComponent) invoker);
            return true;
        }

        setLastInvoker(null);
        return false;
    }

    @Override
    public int getWeight() {
        return MenuWeights.MENU_ENCODE_WEIGHT;
    }

    /* ---------------- Encode submenu ---------------- */

    private List<EncoderOperationMenuItem> encodeItems() {
        List<EncoderOperationMenuItem> items = new ArrayList<>();
        items.add(item("encoder.operation.encode.base64", EncodeDecodeUtils::encodeBase64));
        items.add(item("encoder.operation.encode.base64url", EncodeDecodeUtils::encodeBase64Url));
        items.add(item("encoder.operation.encode.url", EncodeDecodeUtils::encodeUrl));
        items.add(item("encoder.operation.encode.fullurl", EncodeDecodeUtils::encodeFullUrl));
        items.add(item("encoder.operation.encode.asciihex", EncodeDecodeUtils::encodeAsciiHex));
        items.add(item("encoder.operation.encode.html", EncodeDecodeUtils::encodeHtml));
        items.add(item("encoder.operation.encode.fullhtml", EncodeDecodeUtils::encodeFullHtml));
        items.add(item("encoder.operation.encode.encodeuri", EncodeDecodeUtils::encodeUri));
        items.add(
                item(
                        "encoder.operation.encode.encodeuricomponent",
                        EncodeDecodeUtils::encodeUriComponent));
        return items;
    }

    /* ---------------- Decode submenu ---------------- */

    private List<EncoderOperationMenuItem> decodeItems() {
        List<EncoderOperationMenuItem> items = new ArrayList<>();
        items.add(item("encoder.operation.decode.base64", EncodeDecodeUtils::decodeBase64));
        items.add(item("encoder.operation.decode.base64url", EncodeDecodeUtils::decodeBase64Url));
        items.add(item("encoder.operation.decode.url", EncodeDecodeUtils::decodeUrl));
        items.add(item("encoder.operation.decode.fullurl", EncodeDecodeUtils::decodeFullUrl));
        items.add(item("encoder.operation.decode.asciihex", EncodeDecodeUtils::decodeAsciiHex));
        items.add(item("encoder.operation.decode.html", EncodeDecodeUtils::decodeHtml));
        items.add(item("encoder.operation.decode.fullhtml", EncodeDecodeUtils::decodeHtml));
        items.add(item("encoder.operation.decode.decodeuri", EncodeDecodeUtils::decodeUri));
        items.add(
                item(
                        "encoder.operation.decode.decodeuricomponent",
                        EncodeDecodeUtils::decodeUriComponent));
        return items;
    }

    /* ---------------- Hash submenu ---------------- */

    private List<Component> hashItems() {
        List<Component> items = new ArrayList<>();
        items.add(shaSubMenu());
        items.add(mdSubMenu());
        items.add(item("encoder.operation.hash.crc32", HashUtils::crc32));
        items.add(item("encoder.operation.hash.murmurhash3", HashUtils::murmur3));
        items.add(item("encoder.operation.hash.argon2id", HashUtils::argon2id));
        items.add(item("encoder.operation.hash.bcrypt", HashUtils::bcrypt));
        items.add(item("encoder.operation.hash.scrypt", HashUtils::scrypt));
        items.add(item("encoder.operation.hash.pbkdf2", HashUtils::pbkdf2));
        items.add(item("encoder.operation.hash.phpass", HashUtils::phpass));
        items.add(blakeSubMenu());
        items.add(item("encoder.operation.hash.whirlpool", HashUtils::whirlpool));
        items.add(item("encoder.operation.hash.siphash", HashUtils::sipHash));
        items.add(item("encoder.operation.hash.fnv1a", HashUtils::fnv1a));
        return items;
    }

    private EncoderSubMenu shaSubMenu() {
        List<Component> shaItems = new ArrayList<>();
        shaItems.add(item("encoder.operation.hash.sha1", HashUtils::sha1));
        shaItems.add(item("encoder.operation.hash.sha3", HashUtils::sha3Keccak));
        shaItems.add(item("encoder.operation.hash.sha256", HashUtils::sha256));
        shaItems.add(item("encoder.operation.hash.sha512", HashUtils::sha512));
        return new EncoderSubMenu(msg("encoder.operation.hash.sha"), shaItems);
    }

    private EncoderSubMenu mdSubMenu() {
        List<Component> mdItems = new ArrayList<>();
        mdItems.add(item("encoder.operation.hash.md4", HashUtils::md4));
        mdItems.add(item("encoder.operation.hash.md5", HashUtils::md5));
        return new EncoderSubMenu(msg("encoder.operation.hash.md"), mdItems);
    }

    private EncoderSubMenu blakeSubMenu() {
        List<EncoderOperationMenuItem> blakeItems = new ArrayList<>();
        blakeItems.add(item("encoder.operation.hash.blake2", HashUtils::blake2));
        blakeItems.add(item("encoder.operation.hash.blake3", HashUtils::blake3));
        return new EncoderSubMenu(msg("encoder.operation.hash.blake"), blakeItems);
    }

    /* ---------------- Convert submenu ---------------- */

    private List<Component> convertItems() {
        List<Component> items = new ArrayList<>();
        items.add(item("encoder.operation.convert.unicode", ConvertUtils::unicode));
        items.add(utfSubMenu());
        items.add(item("encoder.operation.convert.ascii", Confusables.getInstance()::toAscii));
        items.add(confusablesSubMenu());
        return items;
    }

    private EncoderSubMenu utfSubMenu() {
        List<Component> utfItems = new ArrayList<>();
        utfItems.add(illegalUtf8SubMenu());
        utfItems.add(item("encoder.operation.convert.utf7", ConvertUtils::utf7));
        utfItems.add(item("encoder.operation.convert.utf8", ConvertUtils::utf8));
        utfItems.add(item("encoder.operation.convert.utf16le", ConvertUtils::utf16Le));
        utfItems.add(item("encoder.operation.convert.utf16be", ConvertUtils::utf16Be));
        utfItems.add(item("encoder.operation.convert.utf32", ConvertUtils::utf32));
        utfItems.add(item("encoder.operation.convert.utf32le", ConvertUtils::utf32Le));
        utfItems.add(item("encoder.operation.convert.utf32be", ConvertUtils::utf32Be));
        return new EncoderSubMenu(msg("encoder.operation.convert.utf"), utfItems);
    }

    private EncoderSubMenu illegalUtf8SubMenu() {
        List<Component> items = new ArrayList<>();
        items.add(item("encoder.operation.convert.illegalutf8_2", ConvertUtils::illegalUtf82Bytes));
        items.add(item("encoder.operation.convert.illegalutf8_3", ConvertUtils::illegalUtf83Bytes));
        items.add(item("encoder.operation.convert.illegalutf8_4", ConvertUtils::illegalUtf84Bytes));
        return new EncoderSubMenu(msg("encoder.operation.convert.illegalutf8"), items);
    }

    private EncoderSubMenu confusablesSubMenu() {
        Confusables confusables = Confusables.getInstance();
        List<EncoderOperationMenuItem> glyphItems = new ArrayList<>();
        for (String category : confusables.categories()) {
            glyphItems.add(
                    new EncoderOperationMenuItem(
                            category, text -> confusables.toGlyph(text, category), invokerSupplier));
        }
        return new EncoderSubMenu(msg("encoder.operation.convert.confusables"), glyphItems);
    }

    /* ---------------- Helper ---------------- */

    private EncoderOperationMenuItem item(String key, Function<String, String> op) {
        return new EncoderOperationMenuItem(msg(key), op, invokerSupplier);
    }
}
