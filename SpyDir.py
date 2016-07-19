"""
Module contains classes related to Burp Suite extension
"""
from burp import IBurpExtender  # pylint: disable=import-error
from burp import IBurpExtenderCallbacks  # pylint: disable=import-error
from burp import IContextMenuFactory  # pylint: disable=import-error
from burp import ITab  # pylint: disable=import-error

from java.util import ArrayList, List  # pylint: disable=import-error
from javax.swing import (JMenuItem, JPanel, JTextField, GroupLayout, JTabbedPane, Box,  # pylint: disable=import-error
                         JButton, JLabel, JScrollPane, JTextArea, BorderFactory,
                         JFileChooser, JCheckBox)
from java.net import URL  # pylint: disable=import-error
from java.awt import GridLayout, Dimension, GridBagLayout, GridBagConstraints, Color, Toolkit  # pylint: disable=import-error
from java.awt.event import ComponentListener

from os import walk, path, getcwd
from json import load, dump, dumps
from imp import load_source
class BurpExtender(IBurpExtender, IBurpExtenderCallbacks):
    '''
    Class contains the necessary function to begin the burp extension.
    List of things left to implement:
        Add context menus for URL/cookies
        Add tooltips?
        Reflected Parameters GET/POST vs code level params
    '''
    @staticmethod
    def registerExtenderCallbacks(callbacks):  # pylint: disable=invalid-name
        """
        Default extension method. the objects within are related to the internal tabs
        of the extension
        """
        config_tab = SpyTab(callbacks)
        # callbacks.customizeUiComponent(config_tab)
        callbacks.addSuiteTab(config_tab)


class SpyTab(JPanel, ITab):
    """
    Defines the extension tabs
    """
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
        """
        Terrifically hacked together refresh mechanism
        """
        self.j_tabs.setSelectedIndex(1)
        self.j_tabs.setSelectedIndex(0)
        

    @staticmethod
    def getTabCaption():  # pylint: disable=invalid-name
        """
        Returns the tab name for the Burp UI
        """
        return "SpyDir"

    def getUiComponent(self):  # pylint: disable= invalid-name
        """
        Returns the UI component for the Burp UI
        """
        return self

class Config(ITab):
    """
    Defines the Configuration tab
    """
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
        self.cookies = JTextField(30)
        self.headers = JTextField(30)
        self.restore_conf = JTextField("SpyDir.conf")
        self.url = JTextField(30)
        self.parent_window = parent

        # Initialize local stuff
        tab_constraints = GridBagConstraints()
        labels = JPanel(GridLayout(20, 1))

        # Configure view port
        self.view_port_text.setEditable(False)
        # self.status_field.setPreferredSize(self.status_field.getPreferredSize())

        # Build grid
        labels.add(JLabel("Input Directory:"))
        labels.add(self.dir)
        labels.add(JLabel("String Delimiter:"))
        labels.add(self.delim)
        labels.add(JLabel("Extension Whitelist:"))
        labels.add(self.ext_white_list)
        labels.add(JLabel("URL:"))
        labels.add(self.url)
        labels.add(JLabel("Cookies:"))
        labels.add(self.cookies)
        labels.add(JLabel("HTTP Headers:"))
        labels.add(self.headers)
        labels.add(JButton("Save Config", actionPerformed=self.save))
        labels.add(JButton("Restore Config", actionPerformed=self.restore))
        labels.add(JLabel("Config file:"))
        labels.add(self.restore_conf)
        labels.add(JCheckBox("Attempt to Parse Files for URL patterns?",
                             False, actionPerformed=self.set_parse))
        labels.add(JButton("Specify plugins location", actionPerformed=self.set_plugin_loc))
        labels.add(JButton("Parse Directory", actionPerformed=self.parse))
        labels.add(JButton("Send to Spider", actionPerformed=self.scan))
        # labels.setBorder(BorderFactory.createLineBorder(Color.black))

        # Add things to rows
        tab_constraints.anchor = GridBagConstraints.FIRST_LINE_END
        tab_constraints.gridx = 1
        tab_constraints.gridy = 0
        tab_constraints.fill = GridBagConstraints.HORIZONTAL
        self.tab.add(JButton("Resize screen", actionPerformed=self._resize), tab_constraints)
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

    def _resize(self, event):
        if self.parent_window is not None:
            par_size = self.parent_window.getSize()
            par_size.setSize(par_size.getWidth()*.99, par_size.getHeight()*.9)
            self.tab.setPreferredSize(par_size)
            self.parent_window.validate()
            self.parent_window.switch_focus()
            
    def set_parse(self, event):  # pylint: disable=unused-argument
        """
        Handles the click event from the UI checkbox to attempt code level parsing
        """
        self.parse_files = not self.parse_files
        self._callbacks.printOutput("Setting parse_files to %r" % self.parse_files)

    def restore(self, event):  # pylint: disable=unused-argument
        """
        Attempts to restore the previously saved configuration.
        """
        file_loc = self.restore_conf.getText()
        try:
            with open(file_loc) as loc:
                jdump = load(loc)
        except Exception as exc:
            self._callbacks.printOutput("Exception: %s" % str(exc))
        self.url.setText(jdump.get('URL'))
        self.cookies.setText(jdump.get('Cookies'))
        self.ext_white_list.setText(jdump.get('Extension Whitelist'))
        self.delim.setText(jdump.get('String Delimiter'))
        self.dir.setText(jdump.get("Input Directory"))
        self.headers.setText(jdump.get("Headers"))
        # self._callbacks.printOutput("Parent size %r" % self.parent_window.getSize())
        self.save()

    def save(self, event=None):  # pylint: disable=unused-argument
        """
        Writes out the configuration details to a specified file.
        """
        conf_loc = self.restore_conf.getText() # location to store conf file
        self.config["Input Directory"] = self.dir.getText()
        self.config["String Delimiter"] = self.delim.getText()

        white_list_text = self.ext_white_list.getText()
        if white_list_text != "Extension Whitelist" and white_list_text != "":
            self.restrict_ext = True

        self.config["Extension Whitelist"] = white_list_text.upper()
        temp_url = self.url.getText()
        if not self._callbacks.isInScope(URL(temp_url)):
            self.update_scroll("[!!] URL provided is NOT in Burp Scope!")
        self.config["URL"] = temp_url
        self.config["Cookies"] = self.cookies.getText()
        self.config["Headers"] = self.headers.getText()
        # Wipe the current parse
        self.config["exts"] = {}
        del self.url_reqs[:]
        if conf_loc:
            try:
                with open(conf_loc, 'w') as out_file:
                    dump(self.config, out_file, sort_keys=True, indent=4)
            except Exception as exc:
                self._callbacks.printOutput("Exception: %s" % str(exc))

    def parse(self, event):  # pylint: disable=unused-argument
        """
        Handles the click event from the UI.
        Attempts to parse the given directory (and/or source files) for url endpoints
        Saves the items found within the url_reqs list
        """
        self.save()

        file_set = set()
        fcount = 0
        for dirname, _, filenames in walk(self.config.get("Input Directory")):
            for filename in filenames:
                ext = path.splitext(filename)[1]
                count = self.config['exts'].get(ext, 0)
                count += 1
                self.config['exts'].update({ext:count})
                fcount += 1
                file_url = str(self.config.get("URL"))
                if not self.parse_files:
                    try:
                        file_url += (
                            str(dirname)
                            .split(self.config.get("String Delimiter"))[1]
                            + '/' + filename).replace('\\', '/')
                    except Exception as exc:
                        self._callbacks.printError("Exception parsing:\t%s" % dirname)
                        self._callbacks.printError(str(exc))
                        self._callbacks.printError(str(filename))
                    if self.restrict_ext and len(ext) > 0 and ext.strip().upper() in self.config.get("Extension Whitelist"):
                        # self._callbacks.printOutput("%s:%s" % (ext, str(self.config.get("Extension Whitelist"))))
                        file_set.add(file_url)
                    else:
                        file_set.add(file_url)
                else:
                    # i can haz threading?
                    if self.restrict_ext and len(ext) > 0 and ext.strip().upper() in self.config.get("Extension Whitelist"):
                        file_set.update(self.parse_file(filename, file_url))
                    else:
                        file_set.update(self.parse_file(filename, file_url))

        for item in file_set:
            self.url_reqs.append(item)
        if self.parse_files:
            self.update_scroll("[*] Attempted to parse files"
                               + " for URL patterns.")
        self.update_scroll("[*] Found: %r files.\n[*] Found: %r files to be requested." % (fcount, len(self.url_reqs)))
        if len(self.url_reqs) > 0:
            self.update_scroll("[*] Example URL: %s" % self.url_reqs[0])
        if len(self.config.get('exts')) > 0:
            self.update_scroll("[*] Extensions found: %s"
                               % str(dumps(self.config.get("exts"),
                                           sort_keys=True, indent=4)))

        # self.update_scroll(str(dumps(self.config))) # DEBUG

    def parse_file(self, filename, file_url):
        """
        Attempts to parse a file with the loaded plugins returns set of endpoints
        """
        file_set = set()
        for plug in self.plugins:
            res = plug.run(filename)
            if res is not None:
                for i in res:
                    i = file_url + i
                    file_set.add(i)
        return file_set

    def set_plugin_loc(self, event):  # pylint: disable= unused-argument
        """
        Attempts to load plugins from a specified location
        """
        choose_plugin_location = JFileChooser()
        choose_plugin_location.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        choose_plugin_location.showDialog(self.tab, "Choose Folder")
        chosen_folder = choose_plugin_location.getSelectedFile()
        filename = chosen_folder.getAbsolutePath()
        self._callbacks.printOutput("Attempting to load plugins from: %s" % filename)
        self._plugin_parse(filename)
        self._callbacks.printOutput("Plugins loaded!")  # %s" % self.in_map)

    def _plugin_parse(self, folder):
        """
        Parses a local directory to get the plugins related to code level scanning
        """
        self.plugins = []
        for _, _, filenames in walk(folder):
            for plug in filenames:
                if path.splitext(plug)[1] == ".py":
                    lsource = "%s/%s" % (folder, plug)
                    try:
                        loaded_plug = load_source(plug, lsource)
                        self._callbacks.printOutput("%s loaded!" % loaded_plug.get_name())
                        self.plugins.append(loaded_plug)
                    # One day I'll handle this appropriately
                    except Exception as exc:
                        self._callbacks.printOutput("%s\t%s" % (str(exc), lsource))

        # self._callbacks.printOutput("%s, %s") % (str(plugins), str(type(test)))

    def scan(self, event):  # pylint: disable=unused-argument
        """
        handles the click event from the UI.
        Adds the given URL to the burp scope and sends the requests
        to the burp spider
        """
        temp_url = self.url.getText()
        if not self._callbacks.isInScope(URL(temp_url)):
            self._callbacks.sendToSpider(URL(temp_url))
        self.update_scroll("Sending %d requests to Spider" % len(self.url_reqs))

        for req in self.url_reqs:
            self._callbacks.sendToSpider(URL(req))

    def update_scroll(self, text):
        """
        updates the view_port_text with the new information
        """
        temp = self.view_port_text.getText().strip()
        if text not in temp:
            self.view_port_text.setText("%s\n%s" % (temp, text))
            self.status_field.setViewportView(self.view_port_text)

    @staticmethod
    def getTabCaption():  # pylint: disable= invalid-name
        """
        Returns the name of the Burp Suite Tab
        """
        return "Config"

    def getUiComponent(self):  # pylint: disable= invalid-name
        """
        Returns the UI component for the Burp Suite tab
        """
        return self.tab


class About(ITab):
    """
    Defines the About tab
    """
    def __init__(self, callbacks, parent):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.tab = JPanel(GridBagLayout())
        self.version = "0.8.0"

        about_constraints = GridBagConstraints()

        about = "<html><center><h2>SpyDir</h2>Created By: <em>Ryan Reid</em> (@_aur3lius)<br/>Version: %s</center><br/>" % self.version
        getting_started = """
        <html><em>
        SpyDir is an extension that assists in the enumeration of application<br/>
        endpoints via an input directory containing the application's<br/>
        source code. It provides an option to process files as endpoints,<br/>
        think: ASP, PHP, HTML, or parse files to attempt to enumerate<br/>
        endpoints via plugins, think: MVC. Users may opt to send<br/>
        the discovered endpoints directly to the Burp Spider.</em><br/><br/>
         <b>Getting started:</b><br/>
         <ul>
            <li>Add a local source repository</li>
            <li>Add the target URL</li>
            <li>Use the String delimiter to construct the appropriate directory path (if necessary)</li>
            <li>Alternatively, parse each file by selecting plugins and checking the checkbox</li>
            <li>Explicitly define the file extensions to process</li>
            <li>Parse the directory</li>
            <li>Verify output is correct <b>before</b> sending to spider</li>
            <li>Send requests to the Burp Spider</li>
        </ul></html>
        """
        about_constraints.anchor = GridBagConstraints.FIRST_LINE_START
        about_constraints.weightx = 1.0
        about_constraints.weighty = 1.0
        self.tab.add(JLabel("%s\n%s" % (about, getting_started)), about_constraints)

    @staticmethod
    def getTabCaption():  # pylint: disable= invalid-name
        """
        Returns name of tab for Burp UI
        """
        return "About"
    def getUiComponent(self):  # pylint: disable= invalid-name
        """
        Returns UI component for Burp UI
        """
        return self.tab