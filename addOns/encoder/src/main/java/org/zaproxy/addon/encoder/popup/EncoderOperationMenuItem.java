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
package org.zaproxy.addon.encoder.popup;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;
import javax.swing.text.JTextComponent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;

/**
 * A leaf popup menu item that applies an operation to the currently selected text of the invoking
 * {@code JTextComponent} and replaces the selection with the result, keeping the new text selected
 * so that multiple operations can be chained.
 *
 * <p>Uses a {@link Supplier} to obtain the invoker from the parent menu, since ZAP only calls
 * {@code isEnableForComponent} on top-level popup items, not on nested submenu children.
 */
@SuppressWarnings("serial")
public class EncoderOperationMenuItem extends ExtensionPopupMenuItem {

    private static final Logger LOGGER = LogManager.getLogger(EncoderOperationMenuItem.class);
    private static final ExecutorService EXECUTOR =
            Executors.newCachedThreadPool(
                    r -> {
                        Thread t = new Thread(r, "EncoderOperation");
                        t.setDaemon(true);
                        return t;
                    });

    private final java.util.function.Function<String, String> operation;
    private final Supplier<JTextComponent> invokerSupplier;

    public EncoderOperationMenuItem(
            String label,
            java.util.function.Function<String, String> operation,
            Supplier<JTextComponent> invokerSupplier) {
        super(label);
        this.operation = operation;
        this.invokerSupplier = invokerSupplier;
        addActionListener(e -> performAction());
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private void performAction() {
        JTextComponent invoker = invokerSupplier.get();
        if (invoker == null) {
            return;
        }
        final String selectedText = invoker.getSelectedText();
        if (selectedText == null || selectedText.isEmpty()) {
            return;
        }

        EXECUTOR.execute(
                        () -> {
                            try {
                                String result = operation.apply(selectedText);
                                javax.swing.SwingUtilities.invokeLater(
                                        () -> replaceSelection(invoker, result));
                            } catch (Exception e) {
                                LOGGER.error(
                                        "Error performing operation '{}': {}",
                                        getText(),
                                        e.getMessage(),
                                        e);
                                showErrorDialog(e);
                            }
                        });
    }

    private static void replaceSelection(JTextComponent textComponent, String newText) {
        try {
            int start = textComponent.getSelectionStart();
            int end = textComponent.getSelectionEnd();
            if (start == end) {
                return;
            }
            textComponent.replaceSelection(newText);
            textComponent.setSelectionStart(start);
            textComponent.setSelectionEnd(start + newText.length());
        } catch (RuntimeException e) {
            LOGGER.warn("Could not replace the selected text", e);
        }
    }

    private void showErrorDialog(Exception e) {
        javax.swing.SwingUtilities.invokeLater(
                () ->
                        org.parosproxy.paros.view.View.getSingleton()
                                .showWarningDialog(
                                        Constant.messages.getString(
                                                "encoder.operation.popup.error",
                                                getText(),
                                                e.getMessage() == null
                                                        ? e.toString()
                                                        : e.getMessage())));
    }
}
