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
from java.awt import GridLayout, Dimension, GridBagLayout, GridBagConstraints, Color  # pylint: disable=import-error

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
        config = Config(callbacks)
        comp = Compare(callbacks, config)
        about = About(callbacks)
        configurables = [config, comp, about]
        config_tab = SpyTab(configurables)

        # callbacks.customizeUiComponent(config_tab)
        callbacks.addSuiteTab(config_tab)


class SpyTab(JPanel, ITab):
    """
    Defines the extension tabs
    """
    def __init__(self, tabs):
        super(SpyTab, self).__init__(GroupLayout(self))
        self.build_ui(tabs)

    def build_ui(self, tabs):
        """
        Builds the tabbed pane within the main extension tab
        Tabs are Config, Compare, and About objects
        """
        ui_tab = JTabbedPane()
        for tab in tabs:
            ui_tab.add(tab.getTabCaption(), tab.getUiComponent())
        main_box = Box.createVerticalBox()
        main_box.add(ui_tab)
        main_box.add(Box.createVerticalGlue())
        self.add(main_box)

    @staticmethod
    def getTabCaption():  # pylint: disable=invalid-name
        """
        Returns the tab name for the Burp UI
        """
        return "!APlaceholder"

    def getUiComponent(self):  # pylint: disable= invalid-name
        """
        Returns the UI component for the Burp UI
        """
        return self

class Config():
    """
    Defines the Configuration tab
    """
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.config = {}
        self.restrict_ext = False
        self.url_reqs = []
        self.parse_files = False

        self.tab = JPanel(GridLayout(3, 1))
        # self.tab.setPreferredSize(self.tab.getPreferredSize())
        lower_row = JPanel(GridLayout(1, 1))
        lower_row.setPreferredSize(lower_row.getPreferredSize())
        upper_row = JPanel(GridLayout(1, 2))
        labels = JPanel(GridLayout(10, 2))
        # self.fields = JPanel(GridLayout(8,1))
        self.view_port_text = JTextArea("===SpyDir===")
        self.status_field = JScrollPane(self.view_port_text)

        self.dir = JTextField(60)
        self.delim = JTextField(30)
        self.ext_white_list = JTextField(30)
        self.url = JTextField(60)
        # I'm not sure if these fields are necessary still
        # why not just use Burp func to handle this?
        self.cookies = JTextField(60)
        self.headers = JTextField(30)
        self.restore_conf = JTextField("SpyDir.conf")

        self.view_port_text.setEditable(False)
        # self.restore_conf.setColumns(2)

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
        labels.add(JButton("Parse Directory", actionPerformed=self.parse))
        labels.add(JButton("Send to Spider", actionPerformed=self.scan))

        upper_row.add(labels)
        # upper_row.add(self.fields)
        lower_row.add(self.status_field)
        self.tab.add(upper_row)
        self.tab.add(lower_row)
        self._callbacks.customizeUiComponent(self.tab)
        # self._callbacks.printOutput(getcwd())
        self._plugin_parse()

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

        self.save(None)

    def save(self, event):  # pylint: disable=unused-argument
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
        self.save(None)

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
                    if self.restrict_ext:
                        if len(ext) > 0:
                            if ext.strip().upper() in self.config.get("Extension Whitelist"):
                                #self._callbacks.printOutput("%s:%s" % (ext, str(self.config.get("Extension Whitelist"))))
                                file_set.add(file_url)
                    else:
                        file_set.add(file_url)
                else:
                    # i can haz threading?
                    for plug in self.plugins:
                        res = plug.run(filename)
                        if res is not None:
                            for i in res:
                                i = file_url + i
                                file_set.add(i)

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

    # Should there be a plugins dir config item?

    def _plugin_parse(self):
        """
        Parses a local directory to get the plugins related to code level scanning
        """
        self.plugins = []
        for _, _, filenames in walk(getcwd() + "/plugins"):
            for plug in filenames:
                if path.splitext(plug)[1] == ".py":
                    lsource = "%s/%s/%s" % (getcwd(), "plugins", plug)
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
        temp = self.view_port_text.getText()
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


class Compare():
    '''
    Compare tab in extension. Upon inclusion of 2 sitemaps,
    provides the ability to identify *simple* shared results.
    More complexity = TODO
    '''
    def __init__(self, callbacks, config):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # self.tk = Toolkit.getDefaultToolkit()
        self.conf = config
        self.chosen_import_file = None
        self.in_map = None

        # x_size = self.tk.getScreenSize().getWidth()
        # y_size = self.tk.getScreenSize().getHeight()

        self.tab = JPanel(GridBagLayout())
        self.tab.setMaximumSize(self.tab.getPreferredSize())
        tab_constraints = GridBagConstraints()

        # Top row config
        self.top_row = JPanel(GridBagLayout())
        # self.top_row.setPreferredSize(Dimension(145, 30))
        # self._callbacks.printOutput(str(self.top_row.getSize()))
        tab_constraints.gridx = 0
        self.top_row.add(JButton("Refresh",
                                 actionPerformed=self.refresh),
                         tab_constraints)
        tab_constraints.gridx = 1
        self.top_row.add(JButton("Export Site map",
                                 actionPerformed=self.export_sitemap),
                         tab_constraints)
        tab_constraints.gridx = 2
        self.top_row.add(JButton("Import Site map",
                                 actionPerformed=self.import_sitemap),
                         tab_constraints)
        self.top_row.setPreferredSize(self.top_row.getPreferredSize())
        # self.top_row.setBorder(BorderFactory.createLineBorder(Color.black))

        tab_constraints.gridx = 0
        tab_constraints.gridy = 0
        tab_constraints.anchor = GridBagConstraints.NORTH

        self.tab.add(self.top_row, tab_constraints)


        # Bottom row config
        bottom_row = JPanel(GridBagLayout())
        bottom_row.setPreferredSize(bottom_row.getMaximumSize())
        # bottom_row.setBorder(BorderFactory.createLineBorder(Color.black))

        # self.leftColumn = JPanel(GridBagLayout())
        # self.middleColumn = JPanel(GridBagLayout())
        # self.rightColumn = JPanel(GridBagLayout())


        # Left side
        # self.left_panel = JPanel()
        self.left_text = JTextArea("")
        self.left_text.setEditable(False)
        self.left_results = JScrollPane(self.left_text)
        # self.left_results.setPreferredSize(self.left_results.getPreferredSize())
        # self.left_results.setMaximumSize(Dimension())
        left_label = JLabel("Results #1")

        # Middle pane
        self.middle_text = JTextArea("")
        self.middle_text.setEditable(False)
        self.middle_results = JScrollPane(self.middle_text)
        middle_label = JLabel("Shared Results")

        # Right side
        self.right_text = JTextArea("")
        self.right_text.setEditable(False)
        self.right_results = JScrollPane(self.right_text)
        right_label = JLabel("Results #2")

        # Add labels to bottom_row

        # Top left
        tab_constraints.gridx = 0
        tab_constraints.gridy = 0
        tab_constraints.fill = GridBagConstraints.HORIZONTAL
        bottom_row.add(left_label, tab_constraints)
        # Top Middle
        tab_constraints.gridx = 1
        tab_constraints.gridy = 0
        #tab_constraints.fill = GridBagConstraints.HORIZONTAL
        bottom_row.add(middle_label, tab_constraints)
        # Top Right
        tab_constraints.gridx = 2
        tab_constraints.gridy = 0
        # tab_constraints.fill = GridBagConstraints.HORIZONTAL
        bottom_row.add(right_label, tab_constraints)

        # Add result windows to bottom_row

        # Bottom left
        tab_constraints.gridx = 0
        tab_constraints.gridy = 1
        tab_constraints.ipadx = 320
        tab_constraints.ipady = 400
        tab_constraints.fill = GridBagConstraints.BOTH
        bottom_row.add(self.left_results, tab_constraints)

        # Bottom middle
        tab_constraints.gridx = 1
        tab_constraints.gridy = 1
        # tab_constraints.fill = GridBagConstraints.BOTH
        bottom_row.add(self.middle_results, tab_constraints)


        # Bottom right
        tab_constraints.gridx = 2
        tab_constraints.gridy = 1
        bottom_row.add(self.right_results, tab_constraints)

        tab_constraints.gridx = 0
        tab_constraints.gridy = 1
        tab_constraints.weighty = 1.0
        tab_constraints.weightx = 1.0
        tab_constraints.fill = GridBagConstraints.BOTH

        self.tab.add(bottom_row, tab_constraints)
        self._callbacks.customizeUiComponent(self.tab)

    def refresh(self, event):  # pylint: disable= unused-argument
        """
        Attempts to refresh the Compare tab items.
        Uses the url from the the Config tab as the 1st sitemap
        """
        url = self.conf.url.getText()
        urls = self._callbacks.getSiteMap(url)
        s_map = self.handle_sitemap(urls)

        # self._callbacks.printOutput(str(self.tab.getSize()))
        # self._callbacks.printOutput(str(self.left_results.getSize()))

        if self.chosen_import_file is not None:
            self._callbacks.printOutput("Attempting to compare sitemaps")
            results = self.compare_maps(s_map)

            for codes in results['s_map']:
                self.update_scroll(self.left_text, self.left_results, codes)
                self.update_scroll(self.left_text, self.left_results,
                                   str(dumps(results['s_map'][codes], sort_keys=True, indent=4)))
            for codes in results['shared']:
                self.update_scroll(self.middle_text, self.middle_results, codes)
                self.update_scroll(self.middle_text, self.middle_results,
                                   str(dumps(results['shared'][codes], sort_keys=True, indent=4)))
            for codes in results['in_map']:
                self.update_scroll(self.right_text, self.right_results, codes)
                self.update_scroll(self.right_text, self.right_results,
                                   str(dumps(results['in_map'][codes], sort_keys=True, indent=4)))
            self._callbacks.printOutput("Page refreshed!")

    @staticmethod
    def update_scroll(text_area, scroll_pane, text):
        """
        Updates a given scroll_pane object with new text
        """
        temp = text_area.getText().strip()
        if text not in temp:
            text_area.setText("%s\n%s" % (temp, text))
            scroll_pane.setViewportView(text_area)

    def handle_sitemap(self, site_map):
        """
        Processes the site_map from burp to extract relevant information
        Returns dict of { Response code: [url] }
        """
        resources = {}
        for site in site_map:
            response = site.getResponse()
            if response is not None:
                response = self._helpers.bytesToString(response)
                host = site.getHttpService().getHost()
                port = site.getHttpService().getPort()
                proto = site.getHttpService().getProtocol()
                request = self._helpers.bytesToString(site.getRequest())
                uri = request.split("HTTP")[0].split("/", 1)[1]
                resp_code = str(response.split("HTTP/1.1 ")[1].split(" ")[0])
                url = "%s://%s:%s/%s" %(proto, host, port, uri)
                # self._callbacks.printOutput("request: %s\turi: %s" %(request, uri))
                if resp_code in resources:
                    resources[resp_code].append(url)
                else:
                    resources.update({resp_code: [url]})
        return resources

    def import_sitemap(self, event):  # pylint: disable= unused-argument
        """
        Attempts to import information from previously exported sitemap
        """
        choose_import_file = JFileChooser()
        choose_import_file.showDialog(self.top_row, "Choose File")
        self.chosen_import_file = choose_import_file.getSelectedFile()
        filename = self.chosen_import_file.getAbsolutePath()
        self._callbacks.printOutput("Attempting to import filename: %s" % filename)
        try:
            with open(filename) as in_file:
                self.in_map = load(in_file)
        except Exception as exc:
            self._callbacks.printOutput("Exception: %s" % str(exc))
        self._callbacks.printOutput("Import complete: %s" % self.in_map)

    def compare_maps(self, s_map):
        """
        Compares the sitemaps to determine similar/distinct items from each
        Returns a dictionary object of shared values and separately distinct values
        """
        comp_results = {
            "s_map": {},
            "shared": {},
            "in_map": {}
            }
        for response_code in s_map:
            s_map_urls = s_map.get(response_code, [])
            in_map_urls = self.in_map.get(response_code, [])
            for url in s_map_urls:
                if url in in_map_urls:
                    if response_code in comp_results['shared']:
                        comp_results['shared'].get(response_code).append(url)
                    else:
                        comp_results['shared'].update({response_code: [url]})
                else:
                    if response_code in comp_results['s_map']:
                        comp_results['s_map'].get(response_code).append(url)
                    else:
                        comp_results['s_map'].update({response_code: [url]})
        for response_code in self.in_map:
            s_map_urls = s_map.get(response_code, [])
            in_map_urls = self.in_map.get(response_code, [])
            for url in in_map_urls:
                if url not in comp_results['shared'].get(response_code, ""):
                    if response_code in comp_results['in_map']:
                        comp_results['in_map'].get(response_code).append(url)
                    else:
                        comp_results['in_map'].update({response_code: [url]})
        return comp_results

    def export_sitemap(self, event):  # pylint: disable= unused-argument
        """
        Writes the sitemap for the URL specified in the Config tab to a file in JSON format
        """
        choose_export_file = JFileChooser()
        choose_export_file.showDialog(self.top_row, "Choose File")

        filename = choose_export_file.getSelectedFile().getAbsolutePath()
        self._callbacks.printOutput("Export Sitemap Filename: %s" % str(filename))
        url = self.conf.url.getText()
        output = self._callbacks.getSiteMap(url)
        self._callbacks.printOutput("Printing Sitemap for: %s" % url)
        try:
            with open(filename, 'w') as out_file:
                dump(self.handle_sitemap(output), out_file)
        except Exception as exc:
            self._callbacks.printOutput("Exception: %s" % str(exc))
        self._callbacks.printOutput("Print complete")

    @staticmethod
    def getTabCaption():  # pylint: disable= invalid-name
        """
        Returns name of tab for Burp UI
        """
        return "Compare"
    def getUiComponent(self):  # pylint: disable= invalid-name
        """
        Returns UI component for Burp UI
        """
        return self.tab


class About():
    """
    Defines the About tab
    """
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.tab = JPanel(GridLayout(7, 1))

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
