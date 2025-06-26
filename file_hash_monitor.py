import wx
import hashlib
import os

class FileIntegrityFrame(wx.Frame):
    def __init__(self):
        super().__init__(parent=None, title="File Integrity Monitor", size=(1000, 650))
        self.Center()
        self.files = {}  # filename -> {path, stored_hash, current_hash, status}

        self.InitUI()

    def InitUI(self):
        # Create a panel for the whole frame
        panel = wx.Panel(self)

        # Create horizontal box sizer for sidebar + main area
        hbox = wx.BoxSizer(wx.HORIZONTAL)

        # Sidebar (Fixed width)
        sidebar = wx.Panel(panel, size=(220, -1))
        sidebar.SetBackgroundColour("#f3f4f6")

        sb_sizer = wx.BoxSizer(wx.VERTICAL)
        font_bold = wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_BOLD)
        font_normal = wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_NORMAL)

        self.btn_monitor = wx.Button(sidebar, label="Monitor Files")
        self.btn_monitor.SetFont(font_bold)
        self.btn_about = wx.Button(sidebar, label="About")
        self.btn_about.SetFont(font_normal)

        sb_sizer.AddSpacer(30)
        sb_sizer.Add(self.btn_monitor, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        sb_sizer.AddSpacer(15)
        sb_sizer.Add(self.btn_about, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        sb_sizer.AddStretchSpacer()

        sidebar.SetSizer(sb_sizer)

        # Main Panel with a notebook or stacked panels for pages
        self.main_panel = wx.Panel(panel)
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)

        # Page Monitor Files
        self.page_monitor = wx.Panel(self.main_panel)
        monitor_sizer = wx.BoxSizer(wx.VERTICAL)

        title = wx.StaticText(self.page_monitor, label="File Integrity Monitor")
        title_font = wx.Font(18, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_BOLD)
        title.SetFont(title_font)
        title.SetForegroundColour("#2563eb")
        monitor_sizer.Add(title, 0, wx.ALL, 15)

        # File ListCtrl
        self.file_list = wx.ListCtrl(self.page_monitor, style=wx.LC_REPORT|wx.BORDER_SUNKEN)
        self.file_list.InsertColumn(0, "Filename", width=260)
        self.file_list.InsertColumn(1, "Hash (SHA-256)", width=560)
        self.file_list.InsertColumn(2, "Status", width=120)

        monitor_sizer.Add(self.file_list, 1, wx.EXPAND|wx.LEFT|wx.RIGHT, 15)

        # Buttons horizontal box
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.btn_add = wx.Button(self.page_monitor, label="Add Files")
        self.btn_check = wx.Button(self.page_monitor, label="Check Integrity")
        self.btn_remove = wx.Button(self.page_monitor, label="Remove Selected")

        button_sizer.Add(self.btn_add, 0, wx.ALL, 10)
        button_sizer.Add(self.btn_check, 0, wx.ALL, 10)
        button_sizer.Add(self.btn_remove, 0, wx.ALL, 10)

        monitor_sizer.Add(button_sizer, 0, wx.CENTER)

        # Status text
        self.status_text = wx.StaticText(self.page_monitor, label="")
        font_status = wx.Font(10, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_NORMAL)
        self.status_text.SetFont(font_status)
        self.status_text.SetForegroundColour("#6b7280")
        monitor_sizer.Add(self.status_text, 0, wx.ALL|wx.EXPAND, 15)

        self.page_monitor.SetSizer(monitor_sizer)


        # Page About
        self.page_about = wx.Panel(self.main_panel)
        about_sizer = wx.BoxSizer(wx.VERTICAL)
        about_title = wx.StaticText(self.page_about, label="About File Integrity Monitor")
        about_title.SetFont(title_font)
        about_title.SetForegroundColour("#2563eb")
        about_sizer.Add(about_title, 0, wx.ALL, 15)

        about_text = wx.StaticText(self.page_about, label=
            "This application monitors files by calculating and comparing SHA-256 hash values to ensure file integrity.\n\n"
            "Add your files to track their hashes and check for unauthorized changes.\n\n"
            "Developed with Python & wxPython for a native, fast, and responsive user experience.\n\n"
            "© 2024 Your Company Name"
        )
        about_text.Wrap(760)
        about_sizer.Add(about_text, 0, wx.ALL, 20)
        about_sizer.AddStretchSpacer()

        self.page_about.SetSizer(about_sizer)

        # Add pages to main panel sizer as stacked panels
        self.main_sizer.Add(self.page_monitor, 1, wx.EXPAND)
        self.main_sizer.Add(self.page_about, 1, wx.EXPAND)
        self.main_panel.SetSizer(self.main_sizer)

        # Initially show monitor page only
        self.page_about.Hide()

        # Add sidebar and main_panel to hbox
        hbox.Add(sidebar, 0, wx.EXPAND)
        hbox.Add(self.main_panel, 1, wx.EXPAND|wx.LEFT, 0)

        panel.SetSizer(hbox)

        # Bind buttons
        self.btn_monitor.Bind(wx.EVT_BUTTON, self.on_show_monitor)
        self.btn_about.Bind(wx.EVT_BUTTON, self.on_show_about)
        self.btn_add.Bind(wx.EVT_BUTTON, self.on_add_files)
        self.btn_check.Bind(wx.EVT_BUTTON, self.on_check_integrity)
        self.btn_remove.Bind(wx.EVT_BUTTON, self.on_remove_selected)

    def on_show_monitor(self, event):
        self.btn_monitor.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_BOLD))
        self.btn_about.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_NORMAL))
        self.page_about.Hide()
        self.page_monitor.Show()
        self.main_panel.Layout()

    def on_show_about(self, event):
        self.btn_about.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_BOLD))
        self.btn_monitor.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.FONTWEIGHT_NORMAL))
        self.page_monitor.Hide()
        self.page_about.Show()
        self.main_panel.Layout()

    def on_add_files(self, event):
        with wx.FileDialog(self, "Select files to monitor", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            paths = fileDialog.GetPaths()
        
        added = 0
        for path in paths:
            filename = os.path.basename(path)
            if filename in self.files:
                # Skip duplicates
                continue
            filehash = self.calculate_hash(path)
            if not filehash:
                continue
            self.files[filename] = {
                "path": path,
                "stored_hash": filehash,
                "current_hash": filehash,
                "status": "Unchanged"
            }
            index = self.file_list.InsertItem(self.file_list.GetItemCount(), filename)
            self.file_list.SetItem(index, 1, filehash)
            self.file_list.SetItem(index, 2, "Unchanged")
            added += 1

        self.set_status(f"Added {added} new file(s)." if added else "No new files added (duplicates skipped).")

    def on_check_integrity(self, event):
        if not self.files:
            self.set_status("No files to check. Please add files first.")
            return

        modified = []
        for filename, info in self.files.items():
            new_hash = self.calculate_hash(info["path"])
            if not new_hash:
                # Could show error
                continue
            info["current_hash"] = new_hash
            list_index = self.find_item_index(filename)
            if new_hash == info["stored_hash"]:
                info["status"] = "Unchanged"
                if list_index != -1:
                    self.file_list.SetItem(list_index, 1, new_hash)
                    self.file_list.SetItem(list_index, 2, "Unchanged")
            else:
                info["status"] = "Modified"
                modified.append(filename)
                if list_index != -1:
                    self.file_list.SetItem(list_index, 1, new_hash)
                    self.file_list.SetItem(list_index, 2, "Modified")

        if modified:
            self.set_status(f"{len(modified)} file(s) modified!")
            dlg = wx.MessageDialog(self, 
                               "The following files have been modified:\n" + "\n".join(modified), 
                               "Modified Files", wx.OK | wx.ICON_WARNING)
            dlg.ShowModal()
            dlg.Destroy()
        else:
            self.set_status(f"All {len(self.files)} files unchanged. Integrity verified.")
            dlg = wx.MessageDialog(self, 
                               "All files are unchanged. Integrity verified.", 
                               "Integrity Check", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            dlg.Destroy()

    def on_remove_selected(self, event):
        selected = []
        index = -1
        while True:
            index = self.file_list.GetNextItem(index, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if index == -1:
                break
            selected.append(index)

        if not selected:
            self.set_status("No files selected to remove.")
            return

        for i in reversed(selected):
            filename = self.file_list.GetItemText(i)
            if filename in self.files:
                del self.files[filename]
            self.file_list.DeleteItem(i)
        self.set_status(f"Removed {len(selected)} file(s).")

    def calculate_hash(self, filepath):
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            wx.MessageBox(f"Failed to read file {filepath}.\n\nError: {str(e)}", "Error", wx.OK | wx.ICON_ERROR)
            return None

    def find_item_index(self, filename):
        index = self.file_list.GetFirstItem()
        while index != -1:
            if self.file_list.GetItemText(index) == filename:
                return index
            index = self.file_list.GetNextItem(index)
        return -1

    def set_status(self, text):
        self.status_text = text
        self.SetStatusText(text)


class FileIntegrityApp(wx.App):
    def OnInit(self):
        self.frame = FileIntegrityFrame()
        self.frame.CreateStatusBar()
        self.frame.SetStatusText("")
        self.frame.Show()
        return True


if __name__ == "__main__":
    app = FileIntegrityApp(False)
    app.MainLoop()
