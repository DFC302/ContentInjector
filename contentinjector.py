from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem, JFileChooser, JComboBox, JOptionPane
from java.io import File
import java.awt.event.ActionListener as ActionListener
import base64

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ContentInjector")
        callbacks.registerContextMenuFactory(self)
        self.last_dir = None

    def createMenuItems(self, invocation):
        menu_plain = JMenuItem("Insert File Contents Here")
        menu_plain.addActionListener(FileInsertAction(self, invocation, self.helpers, encode=False))

        menu_b64 = JMenuItem("Insert File Contents (Base64)")
        menu_b64.addActionListener(FileInsertAction(self, invocation, self.helpers, encode=True))

        # New menu item for MIME type replacement
        menu_mime = JMenuItem("Replace with MIME Type...")
        menu_mime.addActionListener(MimeTypeInsertAction(self, invocation, self.helpers))

        return [menu_plain, menu_b64, menu_mime]


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


# -----------------------
# MIME Type replacement feature
# -----------------------

MIME_TYPES = sorted([
    "application/atom+xml",
    "application/epub+zip",
    "application/gzip",
    "application/java-archive",
    "application/json",
    "application/ld+json",
    "application/manifest+json",
    "application/msword",
    "application/octet-stream",
    "application/ogg",
    "application/pdf",
    "application/rtf",
    "application/vnd.amazon.ebook",
    "application/vnd.apple.installer+xml",
    "application/vnd.ms-excel",
    "application/vnd.ms-fontobject",
    "application/vnd.ms-powerpoint",
    "application/vnd.oasis.opendocument.presentation",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.mozilla.xul+xml",
    "application/vnd.rar",
    "application/vnd.visio",
    "application/x-7z-compressed",
    "application/x-abiword",
    "application/x-bzip",
    "application/x-bzip2",
    "application/x-cdf",
    "application/x-csh",
    "application/x-freearc",
    "application/x-httpd-php",
    "application/x-sh",
    "application/x-tar",
    "application/x-zip-compressed",
    "application/xhtml+xml",
    "application/xml",
    "application/zip",
    "audio/3gpp",
    "audio/3gpp2",
    "audio/aac",
    "audio/midi",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "audio/x-midi",
    "font/otf",
    "font/ttf",
    "font/woff",
    "font/woff2",
    "image/apng",
    "image/avif",
    "image/bmp",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg+xml",
    "image/tiff",
    "image/vnd.microsoft.icon",
    "image/webp",
    "text/calendar",
    "text/css",
    "text/csv",
    "text/html",
    "text/javascript",
    "text/markdown",
    "text/plain",
    "text/xml",
    "video/3gpp",
    "video/3gpp2",
    "video/mp2t",
    "video/mp4",
    "video/mpeg",
    "video/ogg",
    "video/webm",
    "video/x-msvideo"
])


class MimeTypeInsertAction(ActionListener):
    def __init__(self, extender, invocation, helpers):
        self.extender = extender
        self.invocation = invocation
        self.helpers = helpers

    def actionPerformed(self, event):
        combo = JComboBox(MIME_TYPES)
        result = JOptionPane.showConfirmDialog(
            None, combo, "Select MIME Type", JOptionPane.OK_CANCEL_OPTION
        )
        if result != JOptionPane.OK_OPTION:
            return

        mime_type = combo.getSelectedItem()
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
                new_data = data[:start] + mime_type + data[end:]
                message.setRequest(self.helpers.stringToBytes(new_data))

            elif context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                data = self.helpers.bytesToString(message.getResponse())
                start, end = sel_bounds if sel_bounds else (len(data), len(data))
                new_data = data[:start] + mime_type + data[end:]
                message.setResponse(self.helpers.stringToBytes(new_data))

            else:
                self.extender.callbacks.issueAlert("Context not supported here")

        except Exception as e:
            self.extender.callbacks.issueAlert("Failed to insert MIME type: %s" % e)
