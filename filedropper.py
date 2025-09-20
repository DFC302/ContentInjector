from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem, JFileChooser
from java.io import File
import java.awt.event.ActionListener as ActionListener
import base64

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("FileDropper")
        callbacks.registerContextMenuFactory(self)
        self.last_dir = None

    def createMenuItems(self, invocation):
        menu_plain = JMenuItem("Insert File Contents Here")
        menu_plain.addActionListener(FileInsertAction(self, invocation, self.helpers, encode=False))

        menu_b64 = JMenuItem("Insert File Contents (Base64)")
        menu_b64.addActionListener(FileInsertAction(self, invocation, self.helpers, encode=True))

        return [menu_plain, menu_b64]

class FileInsertAction(ActionListener):
    def __init__(self, extender, invocation, helpers, encode=False):
        self.extender = extender
        self.invocation = invocation
        self.helpers = helpers
        self.encode = encode

    def actionPerformed(self, event):
        chooser = JFileChooser()
        if self.extender.last_dir:
            chooser.setCurrentDirectory(File(self.extender.last_dir))
        ret = chooser.showOpenDialog(None)
        if ret != JFileChooser.APPROVE_OPTION:
            return

        f = chooser.getSelectedFile()
        self.extender.last_dir = f.getParent()

        try:
            with open(f.getAbsolutePath(), "rb") as fh:
                content = fh.read()
                if self.encode:
                    content = base64.b64encode(content).decode("utf-8")
                else:
                    content = content.decode("utf-8", errors="replace")
        except Exception as e:
            self.extender.callbacks.issueAlert("Could not read file: %s" % e)
            return

        try:
            messages = self.invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                self.extender.callbacks.issueAlert("No HTTP message selected")
                return

            message = messages[0]
            context = self.invocation.getInvocationContext()
            sel_bounds = self.invocation.getSelectionBounds()

            if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                data = self.helpers.bytesToString(message.getRequest())
                start, end = sel_bounds if sel_bounds else (len(data), len(data))
                new_data = data[:start] + content + data[end:]
                message.setRequest(self.helpers.stringToBytes(new_data))

            elif context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                data = self.helpers.bytesToString(message.getResponse())
                start, end = sel_bounds if sel_bounds else (len(data), len(data))
                new_data = data[:start] + content + data[end:]
                message.setResponse(self.helpers.stringToBytes(new_data))

            else:
                self.extender.callbacks.issueAlert("Context not supported here")

        except Exception as e:
            self.extender.callbacks.issueAlert("Failed to insert text: %s" % e)
