"""
Module contains classes related to Burp Suite extension
"""
from burp import (IBurpExtender, IBurpExtenderCallbacks, ITab,
                  IContextMenuFactory)

from javax.swing import (JPanel, JTextField, GroupLayout, JTabbedPane,
                         JButton, JLabel, JScrollPane, JTextArea,
                         JFileChooser, JCheckBox, JMenuItem)
from java.net import URL
from java.awt import GridLayout, GridBagLayout, GridBagConstraints

from os import walk, path
from json import load, dump, dumps
from imp import load_source


class BurpExtender(IBurpExtender, IBurpExtenderCallbacks, IContextMenuFactory):
    """
    Class contains the necessary function to begin the burp extension.
    """
    def __init__(self):
        self.config_tab = None
        self.messages = []
        self._callbacks = None

    def registerExtenderCallbacks(self, callbacks):
        """
        Default extension method. the objects within are related
        to the internal tabs of the extension
        """
        self.config_tab = SpyTab(callbacks)
        self._callbacks = callbacks
        callbacks.addSuiteTab(self.config_tab)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        """Creates the Burp Menu items"""
        context = invocation.getInvocationContext()
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
                or context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
                or context == invocation.CONTEXT_PROXY_HISTORY \
                or context == invocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            self.messages = invocation.getSelectedMessages()
            if len(self.messages) == 1:
                return [JMenuItem('Send URL to SpyDir',
                                  actionPerformed=self.pass_url)]
        else:
            return None

    def pass_url(self, event):
        """Handles the menu event"""
        self.config_tab.update_url(self.messages)


class SpyTab(JPanel, ITab):
    """Defines the extension tabs"""

    def __init__(self, callbacks):
        super(SpyTab, self).__init__(GroupLayout(self))
        self._callbacks = callbacks
        config = Config(self._callbacks, self)
        about = About(self._callbacks, self)
        self.tabs = [config, about]
        self.j_tabs = self.build_ui()
        self.add(self.j_tabs)

    def build_ui(self):
        """
        Builds the tabbed pane within the main extension tab
        Tabs are Config and About objects
        """
        ui_tab = JTabbedPane()
        for tab in self.tabs:
            ui_tab.add(tab.getTabCaption(), tab.getUiComponent())
        return ui_tab

    def switch_focus(self):
        """Terrifically hacked together refresh mechanism"""
        self.j_tabs.setSelectedIndex(1)
        self.j_tabs.setSelectedIndex(0)

    def update_url(self, host):
        """
        Retrieves the selected host information from the menu click
        Sends it to the config tab
        """
        service = host[0].getHttpService()
        url = "%s://%s:%s" % (service.getProtocol(), service.getHost(),
                              service.getPort())
        self.tabs[0].set_url(url)

    @staticmethod
    def getTabCaption():
        """Returns the tab name for the Burp UI"""
        return "SpyDir"

    def getUiComponent(self):
        """Returns the UI component for the Burp UI"""
        return self


class Config(ITab):
    """Defines the Configuration tab"""

    def __init__(self, callbacks, parent):
        # Initialze self stuff
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.config = {}
        self.restrict_ext = False
        self.url_reqs = []
        self.parse_files = False
        self.tab = JPanel(GridBagLayout())
        self.view_port_text = JTextArea("===SpyDir===")
        self.status_field = JScrollPane(self.view_port_text)
        self.dir = JTextField(30)
        self.delim = JTextField(30)
        self.ext_white_list = JTextField(30)
        # I'm not sure if these fields are necessary still
        # why not just use Burp func to handle this?
        # leaving them in case I need it for the HTTP handler later
        # self.cookies = JTextField(30)
        # self.headers = JTextField(30)
        self.restore_conf = JTextField("SpyDir.conf")
        self.url = JTextField(30)
        self.parent_window = parent
        self.plugins = []
        self.loaded_plugins = False
        self.plugin_folder = None

        # Initialize local stuff
        tab_constraints = GridBagConstraints()

        # Configure view port
        self.view_port_text.setEditable(False)

        labels = self.build_ui()

        # Add things to rows
        tab_constraints.anchor = GridBagConstraints.FIRST_LINE_END
        tab_constraints.gridx = 1
        tab_constraints.gridy = 0
        tab_constraints.fill = GridBagConstraints.HORIZONTAL
        self.tab.add(JButton(
                             "Resize screen", actionPerformed=self.resize),
                     tab_constraints)
        tab_constraints.gridx = 0
        tab_constraints.gridy = 1
        tab_constraints.anchor = GridBagConstraints.FIRST_LINE_START
        self.tab.add(labels, tab_constraints)

        tab_constraints.gridx = 1
        tab_constraints.gridy = 1
        tab_constraints.fill = GridBagConstraints.BOTH
        tab_constraints.weightx = 1.0
        tab_constraints.weighty = 1.0

        tab_constraints.anchor = GridBagConstraints.FIRST_LINE_END
        self.tab.add(self.status_field, tab_constraints)
        self._callbacks.customizeUiComponent(self.tab)

    def build_ui(self):
        """Builds the configuration screen"""
        labels = JPanel(GridLayout(21, 1))
        checkbox = JCheckBox("Attempt to parse files for URL patterns?",
                             False, actionPerformed=self.set_parse)
        # The two year old in me is laughing heartily
        plug_butt = JButton("Specify plugins location",
                            actionPerformed=self.set_plugin_loc)
        parse_butt = JButton("Parse directory", actionPerformed=self.parse)
        clear_butt = JButton("Clear text", actionPerformed=self.clear)
        spider_butt = JButton("Send to Spider", actionPerformed=self.scan)

        # Build grid
        labels.add(JLabel("Input Directory:"))
        labels.add(self.dir)
        labels.add(JLabel("String Delimiter:"))
        labels.add(self.delim)
        labels.add(JLabel("Extension Whitelist:"))
        labels.add(self.ext_white_list)
        labels.add(JLabel("URL:"))
        labels.add(self.url)
        # Leaving these here for now.
        # labels.add(JLabel("Cookies:"))
        # labels.add(self.cookies)
        # labels.add(JLabel("HTTP Headers:"))
        # labels.add(self.headers)
        labels.add(checkbox)
        labels.add(plug_butt)
        labels.add(parse_butt)
        labels.add(JButton("Show all endpoints",
                           actionPerformed=self.print_endpoints))
        labels.add(clear_butt)
        labels.add(spider_butt)
        labels.add(JLabel(""))
        labels.add(JLabel("Config file:"))
        labels.add(self.restore_conf)
        labels.add(JButton("Save config", actionPerformed=self.save))
        labels.add(JButton("Restore config", actionPerformed=self.restore))
        # Tool tips!
        self.dir.setToolTipText("Enter the full path to the"
                                " application's source directory")
        self.delim.setToolTipText("Use to manipulate the final URL. "
                                  "See About tab for example.")
        self.ext_white_list.setToolTipText("Define the file"
                                           " extensions to parse")
        self.url.setToolTipText("Enter the target URL")
        self.restore_conf.setToolTipText("Enter the full path to a file "
                                         "to save/restore SpyDir settings")
        checkbox.setToolTipText("Parse files line by line using plugins"
                                " to enumerate language/framework specific"
                                " endpoints")
        parse_butt.setToolTipText("Attempt to enumerate application endpoints")
        clear_butt.setToolTipText("Clear status window")
        spider_butt.setToolTipText("Process discovered endpoints")
        return labels

    def set_url(self, menu_url):
        """Changes the configuration URL to the one from the menu event"""
        self.url.setText(menu_url)

    # Event functions
    def set_parse(self, event):
        """
        Handles the click event from the UI checkbox
        to attempt code level parsing
        """
        self.parse_files = not self.parse_files
        if self.parse_files:
            if not self.loaded_plugins:
                self._plugins_missing_warning()

    def restore(self, event):
        """Attempts to restore the previously saved configuration."""
        file_loc = self.restore_conf.getText()
        try:
            with open(file_loc) as loc:
                jdump = load(loc)
        except Exception as exc:
            self.update_scroll(
                "[!!] Error during restore!\n\tException: %s" % str(exc))
        if jdump is not None:
            self.url.setText(jdump.get('URL'))
            # self.cookies.setText(jdump.get('Cookies'))
            # self.headers.setText(jdump.get("Headers"))
            self.ext_white_list.setText(jdump.get('Extension Whitelist'))
            self.delim.setText(jdump.get('String Delimiter'))
            self.dir.setText(jdump.get("Input Directory"))
            self.plugin_folder = jdump.get("Plugin Folder")
            if self.plugin_folder is not None and len(self.plugins) < 1:
                self._plugin_parse(self.plugin_folder)
            self._update()
        else:
            self.update_scroll("[!!] Restore failed!")

    def save(self, event=None):
        """Writes out the configuration details to a specified file."""
        self._update()
        if not self._callbacks.isInScope(URL(self.url.getText())):
            self.update_scroll("[!!] URL provided is NOT in Burp Scope!")

        if self.restore_conf.getText():
            try:
                with open(self.restore_conf.getText(), 'w') as out_file:
                    dump(self.config, out_file, sort_keys=True, indent=4)
            except Exception as exc:
                self.update_scroll(
                    "[!!] Error during save!\n\tException: %s" % str(exc))

    def parse(self, event):
        """
        Handles the click event from the UI.
        Attempts to parse the given directory
            (and/or source files) for url endpoints
        Saves the items found within the url_reqs list
        """
        self._update()

        file_set = set()
        fcount = 0
        if self.loaded_plugins:
            self.update_scroll("[*] Attempting to parse files" +
                               " for URL patterns. This might take a minute.")
        for dirname, _, filenames in walk(self.config.get("Input Directory")):
            for filename in filenames:
                ext = path.splitext(filename)[1]
                count = self.config['exts'].get(ext, 0)
                count += 1
                self.config['exts'].update({ext: count})
                fcount += 1
                file_url = str(self.config.get("URL"))
                if not self.parse_files:
                    try:
                        file_url += (
                            str(dirname)
                            .split(self.config.get("String Delimiter"))[1] +
                            '/' + filename).replace('\\', '/')
                    except Exception as exc:
                        self.update_scroll("[!!] Error parsing: " +
                                           "%s/%s\n\tException:%s"
                                           % (dirname, filename, str(exc)))
                    if self.restrict_ext:
                        if (len(ext) > 0 and
                            (ext.strip().upper()
                             in self.config.get("Extension Whitelist"))):
                            file_set.add(file_url)
                    else:
                        file_set.add(file_url)
                else:
                    # i can haz threading?
                    if self.loaded_plugins:
                        filename = "%s/%s" % (dirname, filename)
                        if self.restrict_ext:
                            if (len(ext) > 0 and
                                (ext.strip().upper() in
                                 self.config.get("Extension Whitelist"))):
                                file_set.update(
                                    self._parse_file(filename, file_url))
                        else:
                            file_set.update(
                                self._parse_file(filename, file_url))

        for item in file_set:
            self.url_reqs.append(item)
        self._print_parsed_status(fcount)

    def scan(self, event):
        """
        handles the click event from the UI.
        Adds the given URL to the burp scope and sends the requests
        to the burp spider
        """
        temp_url = self.url.getText()
        if not self._callbacks.isInScope(URL(temp_url)):
            self._callbacks.sendToSpider(URL(temp_url))
        self.update_scroll(
            "[*] Sending %d requests to Spider" % len(self.url_reqs))

        for req in self.url_reqs:
            self._callbacks.sendToSpider(URL(req))

    # Plugin functions
    def _parse_file(self, filename, file_url):
        """
        Attempts to parse a file with the loaded plugins
        Returns set of endpoints
        """
        file_set = set()
        with open(filename, 'r') as plug_in:
            lines = plug_in.readlines()
        for plug in self.plugins:
            res = plug.run(lines)
            if len(res) > 0:
                for i in res:
                    i = file_url + i
                    file_set.add(i)
        return file_set

    def set_plugin_loc(self, event):
        """Attempts to load plugins from a specified location"""
        if self.plugin_folder is not None:
            choose_plugin_location = JFileChooser(self.plugin_folder)
        else:
            choose_plugin_location = JFileChooser()
        choose_plugin_location.setFileSelectionMode(
            JFileChooser.DIRECTORIES_ONLY)
        choose_plugin_location.showDialog(self.tab, "Choose Folder")
        chosen_folder = choose_plugin_location.getSelectedFile()
        self.plugin_folder = chosen_folder.getAbsolutePath()
        self._plugin_parse(self.plugin_folder)

    def _plugin_parse(self, folder):
        """
        Parses a local directory to get the plugins
            related to code level scanning
        """
        self.plugins = []
        report = ""
        if len(self.plugins) > 0:
            report = "[*] Plugins reloaded!"
        for _, _, filenames in walk(folder):
            for plug in filenames:
                if path.splitext(plug)[1] == ".py":
                    lsource = "%s/%s" % (folder, plug)
                    try:
                        loaded_plug = load_source(plug, lsource)
                        self.plugins.append(loaded_plug)
                        if not report.startswith("[*]"):
                            report += "%s loaded\n" % loaded_plug.get_name()
                    # One day I'll handle this appropriately
                    except Exception as exc:
                        self.update_scroll(
                            "[!!] Error loading: %s\n\t%s"
                            % (lsource, str(exc)))
        if len(self.plugins) > 0:
            self.loaded_plugins = True
        else:
            report = "[!!] Plugins load failure"
            self.loaded_plugins = False
        self.update_scroll(report)

    # Status window functions
    def _print_parsed_status(self, fcount):
        """Prints the parsed directory status information"""
        if self.parse_files and not self.loaded_plugins:
            self._plugins_missing_warning()
        report = (("[*] Found: %r files.\n" +
                  "[*] Found: %r files to be requested.\n")
                  % (fcount, len(self.url_reqs)))
        self.update_scroll(report)
        if len(self.url_reqs) > 0:
            self.update_scroll("[*] Example URL: %s" % self.url_reqs[0])
        if len(self.config.get('exts')) > 0:
            self.update_scroll("[*] Extensions found: %s"
                               % str(dumps(self.config.get("exts"),
                                           sort_keys=True, indent=4)))

    def _plugins_missing_warning(self):
        """Prints a warning message"""
        self.update_scroll("[!!] No plugins loaded!")

    def clear(self, event):
        """Clears the viewport"""
        self.view_port_text.setText("===SpyDir===")

    def update_scroll(self, text):
        """updates the view_port_text with the new information"""
        temp = self.view_port_text.getText().strip()
        if text not in temp or text[0:4] == "[!!]":
            self.view_port_text.setText("%s\n%s" % (temp, text))
        elif not temp.endswith("[*] Status unchanged"):
            self.view_port_text.setText("%s\n[*] Status unchanged" % temp)

    def print_endpoints(self, event):
        """Prints the discovered endpoints to the status window."""
        req_str = ""
        if len(self.url_reqs) > 0:
            self.update_scroll("[*] Printing all discovered endpoints:")
            for req in self.url_reqs:
                req_str += "    %s\n" % req
        else:
            req_str = "[!!] No endpoints discovered"
        self.update_scroll(req_str)

    # Internal functions
    def _update(self):
        """Updates internal data"""
        self.config["Input Directory"] = self.dir.getText()
        self.config["String Delimiter"] = self.delim.getText()

        white_list_text = self.ext_white_list.getText()
        if white_list_text != "Extension Whitelist" and white_list_text != "":
            self.restrict_ext = True
        self.config["Extension Whitelist"] = white_list_text.upper()
        self.config["URL"] = self.url.getText()
        # self.config["Cookies"] = self.cookies.getText()
        # self.config["Headers"] = self.headers.getText()
        # Wipe the current parse
        self.config["exts"] = {}
        if self.plugin_folder is not None:
            self.config['Plugin Folder'] = self.plugin_folder
        del self.url_reqs[:]

    # Window sizing functions
    def resize(self, event):
        """Resizes the window to better fit Burp"""
        if self.parent_window is not None:
            par_size = self.parent_window.getSize()
            par_size.setSize(par_size.getWidth() * .99,
                             par_size.getHeight() * .9)
            self.tab.setPreferredSize(par_size)
            self.parent_window.validate()
            self.parent_window.switch_focus()

    # ITab required functions
    @staticmethod
    def getTabCaption():
        """Returns the name of the Burp Suite Tab"""
        return "SpyDir"

    def getUiComponent(self):
        """Returns the UI component for the Burp Suite tab"""
        return self.tab


class About(ITab):
    """Defines the About tab"""

    def __init__(self, callbacks, parent):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.tab = JPanel(GridBagLayout())
        self.version = "0.8.2"
        self.parent_window = parent

        about_constraints = GridBagConstraints()

        about = (("<html><center><h2>SpyDir</h2><b>Version:</b> "
                  "%s<br/>Created by: <em>Ryan Reid</em> (@_aur3lius)<br/>"
                  "https://github.com/aur3lius-dev/SpyDir</center><br/>")
                 % self.version)
        getting_started = """
        <em><center>
        SpyDir is an extension that assists in the enumeration of
         application<br/>
        endpoints via an input directory containing the application's<br/>
        source code. It provides an option to process files as endpoints,<br/>
        think: ASP, PHP, HTML, or parse files to attempt to enumerate<br/>
        endpoints via plugins, think: MVC. Users may opt to send the<br/>
        discovered endpoints directly to the Burp Spider.
        </center></em><br/><br/>
         <b>Getting started:</b><br/>
         <ul>
            <li>Add a local source repository</li>
            <li>Add the target URL</li>
            <li>Use the String delimiter to construct the appropriate
             directory path (if necessary)</li>
            <li>Alternatively, parse each file by selecting plugins
             and checking the checkbox</li>
            <li>Explicitly define the file extensions to process</li>
            <li>Parse the directory</li>
            <li>Verify output is correct <b>before</b> sending to spider</li>
            <li>Send requests to the Burp Spider</li>
        </ul>
        """
        advanced_info = """
        <html><b>String Delimiter</b><br/>
        String Delimiter
        allows us to append the necessary section of the folder structure.
        <br/>
        Suppose the target application is hosted at the following URL:
        https://localhost:8080. <br/>The target code base is stored in:
        'C:\Source\TestApp'. <br/>Within the TestApp folder there is a
        subfolder, 'views', with static .html files.<br/>
        In this case the String Delimiter will need to equal 'TestApp'.
        <br/>With the expectation that the tool will produce an example URL
        will such as:<br/>https://localhost:8080/views/view1.html.<br/>
        <b>Note:</b> String Delimiter is ignored if parsing files using
        plugins!
        </html>"""
        about_constraints.anchor = GridBagConstraints.FIRST_LINE_START
        about_constraints.weightx = 1.0
        about_constraints.weighty = 1.0
        self.tab.add(JLabel("%s\n%s\n%s" % (about, getting_started, advanced_info)),
                     about_constraints)

    @staticmethod
    def getTabCaption():
        """Returns name of tab for Burp UI"""
        return "About"

    def getUiComponent(self):
        """Returns UI component for Burp UI"""
        return self.tab
