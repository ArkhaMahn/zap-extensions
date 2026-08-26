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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.function.Function;
import javax.swing.text.JTextComponent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;

/**
 * A leaf popup menu item that applies an operation to the currently selected text of the invoking
 * {@code JTextComponent} and replaces the selection with the result, keeping the new text selected
 * so that multiple operations can be chained.
 */
@SuppressWarnings("serial")
public class EncoderOperationMenuItem extends ExtensionPopupMenuItem {

    private static final Logger LOGGER = LogManager.getLogger(EncoderOperationMenuItem.class);

    private final Function<String, String> operation;
    private JTextComponent lastInvoker;

    public EncoderOperationMenuItem(String label, Function<String, String> operation) {
        super(label);
        this.operation = operation;
        addActionListener(new PerformActionListener());
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (isInResponseView(invoker)) {
            lastInvoker = null;
            return false;
        }
        if (invoker instanceof JTextComponent) {
            JTextComponent textComponent = (JTextComponent) invoker;
            String selectedText = textComponent.getSelectedText();
            boolean hasSelection = selectedText != null && !selectedText.isEmpty();
            setEnabled(hasSelection);
            if (hasSelection) {
                lastInvoker = textComponent;
            }
            return true;
        }

        lastInvoker = null;
        return false;
    }

    /**
     * Tells whether the given component is inside the Response view, where the menu is not shown.
     */
    private static boolean isInResponseView(Component component) {
        for (Component c = component; c != null; c = c.getParent()) {
            if (c instanceof HttpPanelResponse) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private void performAction() {
        if (lastInvoker == null) {
            return;
        }
        final JTextComponent invoker = lastInvoker;
        final String selectedText = invoker.getSelectedText();
        if (selectedText == null || selectedText.isEmpty()) {
            return;
        }

        // Some operations (Argon2id, scrypt, bcrypt, ...) are slow, so run off the EDT.
        new Thread(
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
                        },
                        "EncoderOperation-" + getText())
                .start();
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

    private class PerformActionListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            performAction();
        }
    }
}
