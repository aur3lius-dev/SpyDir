"""
Module contains classes related to Burp Suite extension
"""
from burp import (IBurpExtender, IBurpExtenderCallbacks, ITab,
                  IContextMenuFactory)

from javax.swing import (JPanel, JTextField, GroupLayout, JTabbedPane,
                         JButton, JLabel, JScrollPane, JTextArea,
                         JFileChooser, JCheckBox, JMenuItem, JFrame, JViewport)

from java.net import URL, MalformedURLException
from java.awt import GridLayout, GridBagLayout, GridBagConstraints, Dimension

from os import walk, path
from json import loads, dumps
from imp import load_source


VERSION = "0.8.5"


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
        about = About(self._callbacks)
        # plugs = Plugins(self._callbacks)
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
        self.config = {}
        self.ext_stats = {}
        self.url_reqs = []
        self.parse_files = False
        self.tab = JPanel(GridBagLayout())
        self.view_port_text = JTextArea("===SpyDir===")
        self.delim = JTextField(30)
        self.ext_white_list = JTextField(30)
        # I'm not sure if these fields are necessary still
        # why not just use Burp func to handle this?
        # leaving them in case I need it for the HTTP handler later
        # self.cookies = JTextField(30)
        # self.headers = JTextField(30)
        self.url = JTextField(30)
        self.parent_window = parent
        self.plugins = {}
        self.loaded_p_list = set()
        self.loaded_plugins = False
        self.config['Plugin Folder'] = None
        self.double_click = False
        self.source_input = ""
        self.print_stats = True
        self.curr_conf = JLabel()
        self.window = JFrame("Select plugins",
                             preferredSize=(200, 250),
                             windowClosing=self.p_close)
        self.window.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)
        self.window.setVisible(False)

        # Initialize local stuff
        tab_constraints = GridBagConstraints()
        status_field = JScrollPane(self.view_port_text)

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
        self.tab.add(status_field, tab_constraints)
        try:
            self._callbacks.customizeUiComponent(self.tab)
        except Exception:
            pass

    def build_ui(self):
        """Builds the configuration screen"""
        labels = JPanel(GridLayout(21, 1))
        checkbox = JCheckBox("Attempt to parse files for URL patterns?",
                             False, actionPerformed=self.set_parse)
        stats_box = JCheckBox("Show stats?", True,
                              actionPerformed=self.set_show_stats)
        # The two year old in me is laughing heartily
        plug_butt = JButton("Specify plugins location",
                            actionPerformed=self.set_plugin_loc)
        load_plug_butt = JButton("Select plugins",
                                 actionPerformed=self.p_build_ui)
        parse_butt = JButton("Parse directory", actionPerformed=self.parse)
        clear_butt = JButton("Clear text", actionPerformed=self.clear)
        spider_butt = JButton("Send to Spider", actionPerformed=self.scan)
        save_butt = JButton("Save config", actionPerformed=self.save)
        rest_butt = JButton("Restore config", actionPerformed=self.restore)
        source_butt = JButton("Input Source File/Directory",
                              actionPerformed=self.get_source_input)

        # Build grid
        labels.add(source_butt)
        labels.add(self.curr_conf)
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
        labels.add(stats_box)
        labels.add(plug_butt)
        labels.add(parse_butt)
        labels.add(JButton("Show all endpoints",
                           actionPerformed=self.print_endpoints))
        labels.add(clear_butt)
        labels.add(spider_butt)
        labels.add(JLabel(""))
        labels.add(save_butt)
        labels.add(rest_butt)
        labels.add(load_plug_butt)
        # Tool tips!
        self.delim.setToolTipText("Use to manipulate the final URL. "
                                  "See About tab for example.")
        self.ext_white_list.setToolTipText("Define a comma delimited list of"
                                           " file extensions to parse. Use *"
                                           " to parse all files.")
        self.url.setToolTipText("Enter the target URL")
        checkbox.setToolTipText("Parse files line by line using plugins"
                                " to enumerate language/framework specific"
                                " endpoints")
        parse_butt.setToolTipText("Attempt to enumerate application endpoints")
        clear_butt.setToolTipText("Clear status window and the parse results")
        spider_butt.setToolTipText("Process discovered endpoints")
        save_butt.setToolTipText("Saves the current config settings")
        rest_butt.setToolTipText("<html>Restores previous config settings:"
                                 "<br/>-Input Directory<br/>-String Delim"
                                 "<br/>-Ext WL<br/>-URL<br/>-Plugins")
        source_butt.setToolTipText("Select the application's "
                                   "source directory or file to parse")

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
        jdump = None
        try:
            jdump = loads(self._callbacks.loadExtensionSetting("config"))
        except Exception as exc:  # Generic exception thrown directly to user
            self.update_scroll(
                "[!!] Error during restore!\n\tException: %s" % str(exc))
        if jdump is not None:
            self.url.setText(jdump.get('URL'))
            # self.cookies.setText(jdump.get('Cookies'))
            # self.headers.setText(jdump.get("Headers"))
            ewl = ""
            for ext in jdump.get('Extension Whitelist'):
                ewl += ext + ", "
            self.ext_white_list.setText(ewl[:-2])
            self.delim.setText(jdump.get('String Delimiter'))
            self.source_input = jdump.get("Input Directory")
            self.config['Plugin Folder'] = jdump.get("Plugin Folder")
            if (self.config['Plugin Folder'] is not None and
                    (len(self.plugins.values()) < 1)):
                self._load_plugins(self.config['Plugin Folder'])
            self._update()
            self.update_scroll("[^] Restore complete!")
        else:
            self.update_scroll("[!!] Restore failed!")

    def save(self, event=None):
        """
        Saves the configuration details to a Burp Suite's persistent store.
        """
        self._update()
        try:
            if not self._callbacks.isInScope(URL(self.url.getText())):
                self.update_scroll("[!!] URL provided is NOT in Burp Scope!")
        except MalformedURLException:  # If url field is blank we'll
            pass                       # still save the settings.

        try:
            self._callbacks.saveExtensionSetting("config", dumps(self.config))
            self.update_scroll("[^] Settings saved!")
        except Exception:
            self.update_scroll("[!!] Error saving settings to Burp Suite!")

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
        other_dirs = set()
        self.ext_stats = {}
        proto = "http://"
        if self.loaded_plugins:
            self.update_scroll("[^] Attempting to parse files" +
                               " for URL patterns. This might take a minute.")
        if path.isdir(self.source_input):
            for dirname, _, filenames in walk(self.source_input):
                for filename in filenames:
                    fcount += 1
                    ext = path.splitext(filename)[1]
                    count = self.ext_stats.get(ext, 0) + 1
                    filename = "%s/%s" % (dirname, filename)
                    self.ext_stats.update({ext: count})
                    if self.parse_files:
                        # i can haz threading?
                        file_set.update(self._code_as_endpoints(filename, ext))
                    elif self._ext_test(ext):
                        r_files, oths = self._files_as_endpoints(filename, ext)
                        file_set.update(r_files)
                        other_dirs.update(oths)
        elif path.isfile(self.source_input):
            ext = path.splitext(self.source_input)[1]
            file_set.update(self._code_as_endpoints(self.source_input, ext))
        else:
            self.update_scroll("[!!] Input Directory is not valid!")
        if len(other_dirs) > 0:
            self.update_scroll("[*] Found files matching file extension in:\n")
            for other_dir in other_dirs:
                self.update_scroll(" " * 4 + "%s\n" % other_dir)
        for item in file_set:
            if item.startswith("http://") or item.startswith("https://"):
                proto = item.split("//")[0] + '//'
                item = item.replace(proto, "")
            self.url_reqs.append(proto + item.replace('//', '/'))
        self._print_parsed_status(fcount)
        return (other_dirs, self.url_reqs)

    def scan(self, event):
        """
        handles the click event from the UI.
        Adds the given URL to the burp scope and sends the requests
        to the burp spider
        """
        temp_url = self.url.getText()
        if not self._callbacks.isInScope(URL(temp_url)):
            if not self.double_click:
                self.update_scroll("[!!] URL is not in scope! Press Send to "
                                   "Spider again to add to scope and scan!")
                self.double_click = True
                return
            else:
                self._callbacks.sendToSpider(URL(temp_url))
        self.update_scroll(
            "[^] Sending %d requests to Spider" % len(self.url_reqs))
        for req in self.url_reqs:
            self._callbacks.sendToSpider(URL(req))

    def clear(self, event):
        """Clears the viewport and the current parse exts"""
        self.view_port_text.setText("===SpyDir===")
        self.ext_stats = {}

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

    def set_show_stats(self, event):
        """Modifies the show stats setting"""
        self.print_stats = not self.print_stats

    def get_source_input(self, event):
        """Sets the source dir/file for parsing"""
        source_chooser = JFileChooser()
        source_chooser.setFileSelectionMode(
            JFileChooser.FILES_AND_DIRECTORIES)
        source_chooser.showDialog(self.tab, "Choose Source Location")
        chosen_source = source_chooser.getSelectedFile()
        try:
            self.source_input = chosen_source.getAbsolutePath()
        except AttributeError:
            pass
        if self.source_input is not None:
            self.update_scroll("[*] Source location: %s" % self.source_input)
            self.curr_conf.setText(self.source_input)

    # Plugin functions
    def _parse_file(self, filename, file_url):
        """
        Attempts to parse a file with the loaded plugins
        Returns set of endpoints
        """
        file_set = set()
        with open(filename, 'r') as plug_in:
            lines = plug_in.readlines()
        ext = path.splitext(filename)[1].upper()
        if ext in self.plugins.keys():
            for plug in self.plugins.get(ext):
                if plug.enabled:
                    res = plug.run(lines)
                    if len(res) > 0:
                        for i in res:
                            i = file_url + i
                            file_set.add(i)
        elif ext == '.TXT' and self._ext_test(ext):
            for i in lines:
                i = file_url + i
                file_set.add(i.strip())
        return file_set

    def set_plugin_loc(self, event):
        """Attempts to load plugins from a specified location"""
        if self.config['Plugin Folder'] is not None:
            choose_plugin_location = JFileChooser(self.config['Plugin Folder'])
        else:
            choose_plugin_location = JFileChooser()
        choose_plugin_location.setFileSelectionMode(
            JFileChooser.DIRECTORIES_ONLY)
        choose_plugin_location.showDialog(self.tab, "Choose Folder")
        chosen_folder = choose_plugin_location.getSelectedFile()
        self.config['Plugin Folder'] = chosen_folder.getAbsolutePath()
        self._load_plugins(self.config['Plugin Folder'])

    def _load_plugins(self, folder):
        """
        Parses a local directory to get the plugins
            related to code level scanning
        """
        report = ""
        if len(self.plugins.keys()) > 0:
            report = "[^] Plugins reloaded!"
        for _, _, filenames in walk(folder):
            for p_name in filenames:
                n_e = path.splitext(p_name)  # n_e = name_extension
                if n_e[1] == ".py":
                    f_loc = "%s/%s" % (folder, p_name)
                    loaded_plug = self._validate_plugin(n_e[0], f_loc)
                    if loaded_plug:
                        self.loaded_p_list.add(loaded_plug)
                        if not report.startswith("[^]"):
                            report += "%s loaded\n" % loaded_plug.get_name()

        self._dictify(self.loaded_p_list)
        if len(self.plugins.keys()) > 0:
            self.loaded_plugins = True
        else:
            report = "[!!] Plugins load failure"
            self.loaded_plugins = False
        self.update_scroll(report)
        return report

    def _validate_plugin(self, p_name, f_loc):
        """
        Attempts to verify the manditory plugin functions to prevent broken
        plugins from loading.
        Generates an error message if plugin does not contain an appropriate
        function.
        """
        # Load the plugin
        try:
            plug = load_source(p_name, f_loc)
        except Exception as exc:  # this needs to be generic.
            self.update_scroll(
                "[!!] Error loading: %s\n\tType:%s Error: %s"
                % (f_loc, type(exc), str(exc)))
        # Verify the plugin's functions
        funcs = dir(plug)
        err = []
        if "get_name" not in funcs:
            err.append("get_name()")
        if "get_ext" not in funcs:
            err.append("get_ext()")
        if "run" not in funcs:
            err.append("run()")

        # Report errors & return
        if len(err) < 1:
            return Plugin(plug, True)
        else:
            for issue in err:
                self.update_scroll("[!!] %s is missing: %s func" %
                                   (p_name, issue))
            return None

    def _dictify(self, plist):
        """Converts the list of loaded plugins (plist) into a dictionary"""
        for p in plist:
            exts = p.get_ext().upper()
            for ext in exts.split(","):
                prev_load = self.plugins.get(ext, [])
                prev_load.append(p)
                self.plugins[ext] = prev_load

    # Status window functions
    def _print_parsed_status(self, fcount):
        """Prints the parsed directory status information"""
        if self.parse_files and not self.loaded_plugins:
            self._plugins_missing_warning()
        if len(self.url_reqs) > 0:
            self.update_scroll("[*] Example URL: %s" % self.url_reqs[0])

        if self.print_stats:
            report = (("[*] Found: %r files to be requested.\n\n" +
                       "[*] Stats: \n    " +
                       "Found: %r files.\n") % (len(self.url_reqs), fcount))
            if len(self.ext_stats) > 0:
                report += ("[*] Extensions found: %s"
                           % str(dumps(self.ext_stats,
                                       sort_keys=True, indent=4)))
        else:
            report = ("[*] Found: %r files to be requested.\n" %
                      len(self.url_reqs))
        self.update_scroll(report)
        return report

    def _plugins_missing_warning(self):
        """Prints a warning message"""
        self.update_scroll("[!!] No plugins loaded!")

    def update_scroll(self, text):
        """Updates the view_port_text with the new information"""
        temp = self.view_port_text.getText().strip()
        if text not in temp or text[0:4] == "[!!]":
            self.view_port_text.setText("%s\n%s" % (temp, text))
        elif not temp.endswith("[^] Status unchanged"):
            self.view_port_text.setText("%s\n[^] Status unchanged" % temp)

    # Internal functions
    def _code_as_endpoints(self, filename, ext):
        file_set = set()
        file_url = self.config.get("URL")
        if self.loaded_plugins or ext == '.txt':
            if self._ext_test(ext):
                file_set.update(
                    self._parse_file(filename, file_url))
            else:
                file_set.update(
                    self._parse_file(filename, file_url))
        return file_set

    def _files_as_endpoints(self, filename, ext):
        """Generates endpoints via files with the appropriate extension(s)"""
        file_url = self.config.get("URL")
        broken_splt = ""
        other_dirs = set()  # directories outside of the String Delim.
        file_set = set()
        str_del = self.config.get("String Delimiter")
        if not str_del:
            self.update_scroll("[!!] No available String Delimiter!")
            return
        spl_str = filename.split(str_del)

        try:
            # Fix for index out of bounds exception while parsing
            # subfolders _not_ included by the split
            if len(spl_str) > 1:
                file_url += ((spl_str[1])
                             .replace('\\', '/'))
            else:
                broken_splt = filename.split(self.source_input)[1]
                other_dirs.add(broken_splt)
        except Exception as exc:  # Generic exception thrown directly to user
            self.update_scroll("[!!] Error parsing: " +
                               "%s\n\tException: %s"
                               % (filename, str(exc)))
        if self._ext_test(ext):
            if file_url != self.config.get("URL"):
                file_set.add(file_url)
        else:
            other_dirs.discard(broken_splt)
        return file_set, other_dirs

    def _ext_test(self, ext):
        """Litmus test for extension whitelist"""
        val = False
        if len(self.config.get("Extension Whitelist")) > 0:
            val = (len(ext) > 0 and
                   (ext.strip().upper()
                    in self.config.get("Extension Whitelist")))
        elif "*" in self.config.get("Extension Whitelist"):
            val = True
        return val

    def _update(self):
        """Updates internal data"""
        self.config["Input Directory"] = self.source_input
        self.config["String Delimiter"] = self.delim.getText()

        white_list_text = self.ext_white_list.getText()
        self.config["Extension Whitelist"] = white_list_text.upper().split(',')
        file_url = self.url.getText()
        if not (file_url.startswith('https://') or file_url.startswith('http://')):
            self.update_scroll("[!] Assuming protocol! Default value: 'http://'")
            file_url = 'http://' + file_url
            self.url.setText(file_url)

        if not file_url.endswith('/') and file_url != "":
            file_url += '/'

        self.config["URL"] = file_url
        # self.config["Cookies"] = self.cookies.getText()
        # self.config["Headers"] = self.headers.getText()
        del self.url_reqs[:]
        self.curr_conf.setText(self.source_input)

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

    def p_close(self, event):
        """
        Handles the window close event.
        """
        self.window.setVisible(False)
        self.window.dispose()

    def p_build_ui(self, event):
        """
        Adds a list of checkboxes, one for each loaded plugin
        to the Selct plugins window
        """
        if not self.loaded_p_list:
            self.update_scroll("[!!] No plugins loaded!")
            return

        scroll_pane = JScrollPane()
        scroll_pane.setPreferredSize(Dimension(200, 250))
        check_frame = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridy = 0
        constraints.anchor = GridBagConstraints.FIRST_LINE_START

        for plug in self.loaded_p_list:
            check_frame.add(JCheckBox(plug.get_name(), plug.enabled,
                                      actionPerformed=self.update_box),
                            constraints)
            constraints.gridy += 1

        vport = JViewport()
        vport.setView(check_frame)
        scroll_pane.setViewport(vport)
        self.window.contentPane.add(scroll_pane)
        self.window.pack()
        self.window.setVisible(True)

    def update_box(self, event):
        """
        Handles the check/uncheck event for the plugin's box.
        """
        for plug in self.loaded_p_list:
            if plug.get_name() == event.getActionCommand():
                plug.enabled = not plug.enabled
                if plug.enabled:
                    self.update_scroll("[^] Enabled: %s" %
                                       event.getActionCommand())
                else:
                    self.update_scroll("[^] Disabled: %s" %
                                       event.getActionCommand())

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

    def __init__(self, callbacks):
        self._callbacks = callbacks
        self.tab = JPanel(GridBagLayout())

        about_constraints = GridBagConstraints()

        about_author = (("<html><center><h2>SpyDir</h2><b>Version:</b> "
                         "%s<br/>Created by: <em>Ryan Reid</em>"
                         " (@_aur3lius)<br/>https://github.com/aur3lius-dev/"
                         "SpyDir</center><br/>")
                        % VERSION)
        about_spydir = """<em><center>
        SpyDir is an extension that assists in the enumeration of
        application<br/>
        endpoints via an input directory containing the application's<br/>
        source code. It provides an option to process files as endpoints,<br/>
        think: ASP, PHP, HTML, or parse files to attempt to enumerate<br/>
        endpoints via plugins, think: MVC. Users may opt to send the<br/>
        discovered endpoints directly to the Burp Spider.
        </center></em><br/>
        This tool is in <b>Alpha</b>! <b>Please</b> provide feedback on the
        GitHub page!<br/><br/>"""
        getting_started = """<b>Getting started:</b><br/>
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
        advanced_info = r"""<html><b>String Delimiter</b><br/>
        String Delimiter allows us to append the necessary section
        of the folder structure.<br/>
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
        self.tab.add(JLabel("%s\n%s\n%s\n%s" % (about_author, about_spydir,
                                                getting_started,
                                                advanced_info)),
                     about_constraints)

    @staticmethod
    def getTabCaption():
        """Returns name of tab for Burp UI"""
        return "About"

    def getUiComponent(self):
        """Returns UI component for Burp UI"""
        return self.tab


class Plugin():
    """Defines attributes for loaded extensions"""

    def __init__(self, plugin, enabled):
        self.plug = plugin
        self.name = plugin.get_name()
        self.exts = plugin.get_ext()
        self.enabled = enabled

    def run(self, lines):
        """Runs the plugin"""
        return self.plug.run(lines)

    def get_name(self):
        """Returns the name of the plugin"""
        return self.name

    def get_ext(self):
        """Returns the extension of the plugin"""
        return self.exts
