# ContentInjector


<p align="center">
  <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/e7ab6fc6-a3ac-4551-b871-307b7c1e9b5d" />
</p>

ContentInjector is a Burp Suite extension designed to streamline testing of file upload functionalities and HTTP content manipulation. It allows pentesters and security researchers to quickly load the contents of a file into HTTP requests or responses. With just a few clicks from the context menu, you can insert raw or Base64-encoded data at your cursor position or replace selected text, streamlining testing workflows and payload injection. The extension also enables users to highlight and replace MIME types using a predefined list of common MIME types, making content-type manipulation faster and more consistent.

## Features
* Context Menu Integration – Right-click in Repeater, Proxy, or other editors to access the extension.
* Insert Anywhere – Replace selected text or insert content at the cursor position.
* Raw or Base64 – Choose to insert the file as plain text or Base64-encoded for payload testing.
* Last Directory Memory – Remembers the last directory used for quick file access.
* Supports Requests and Responses – Works in both HTTP requests and responses.
* Enable highlighting and replacement of MIME types from a standardized list of common MIME types.

## Installation
1. Open Burp Suite and go to Extender → Extensions.
2. Click Add, select Python (Jython) as the extension type.
3. Load the FileDropper.py file.

## Usage
1. Right-click inside a request or response editor.
2. Select Insert File Contents Here or Insert File Contents (Base64).
3. Pick the file from your local filesystem.
4. The contents will be inserted at your cursor or replace your selection.

### Replace MIME TYPE
1. Highlight the current MIME type.
2. Right-click inside a request or response editor.
3. Select Replace with MIME Type.
4. Pick a common MIME type from the list of common MIME types.
5. The current MIME type will then be replaced with the selected MIME type.

## Requirements
* Burp Suite Professional or Community Edition
* Jython (compatible with Burp Suite version)
