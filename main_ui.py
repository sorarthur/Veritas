import tkinter
from tkinter import ttk # Import ttk for the Treeview widget
from tkinter import filedialog, messagebox
import malware_scanner
import metadata_extractor
import os

# --- THEME DEFINITION ---
THEME = {
    "root_bg": "#212121",
    "widget_bg": "#2c3e50",
    "text_fg": "#ecf0f1",
    "button_hover_bg": "#34495e",
    "button_active_bg": "#4a6572",
    "cursor_color": "#ffffff",
    "tree_heading_bg": "#34495e",
    "tree_heading_fg": "#ecf0f1",
    "tree_row_odd": "#2c3e50",
    "tree_row_even": "#34495e",
    "tree_selected_bg": "#3498db",
    "font_family": "Segoe UI",
    "font_size": 10,
    "border_radius": 15
}

# --- CUSTOM WIDGET: RoundedButton ---
class RoundedButton(tkinter.Canvas):
    def __init__(self, parent, text, command, **kwargs):
        self.bg_color = kwargs.pop("bg", THEME["widget_bg"])
        self.fg_color = kwargs.pop("fg", THEME["text_fg"])
        self.hover_color = kwargs.pop("hover_color", THEME["button_hover_bg"])
        self.active_color = kwargs.pop("active_color", THEME["button_active_bg"])
        self.font = kwargs.pop("font", (THEME["font_family"], THEME["font_size"], "bold"))
        self.radius = kwargs.pop("radius", THEME["border_radius"])
        super().__init__(parent, highlightthickness=0, **kwargs)
        self.configure(bg=parent.cget("bg"))
        self.command = command
        self.text = text
        self._state = "normal"
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Configure>", self._on_resize)
    def draw(self, color):
        self.delete("all")
        width, height = self.winfo_width(), self.winfo_height()
        if width <= 1 or height <= 1: return
        radius = min(self.radius, width/2, height/2)
        bg = color
        self.create_polygon( (radius, 0, width-radius, 0, width, radius, width, height-radius, width-radius, height, radius, height, 0, height-radius, 0, radius), fill=bg, smooth=True )
        self.create_text(width/2, height/2, text=self.text, font=self.font, fill=self.fg_color)
    def _on_resize(self, event):
        if self._state == "hover": self.draw(color=self.hover_color)
        elif self._state == "active": self.draw(color=self.active_color)
        else: self.draw(color=self.bg_color)
    def _on_enter(self, event): self._state = "hover"; self.draw(color=self.hover_color)
    def _on_leave(self, event): self._state = "normal"; self.draw(color=self.bg_color)
    def _on_click(self, event): self._state = "active"; self.draw(color=self.active_color)
    def _on_release(self, event):
        if 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
            self._state = "hover"; self.draw(color=self.hover_color)
            if self.command: self.command()
        else: self._state = "normal"; self.draw(color=self.bg_color)


# --- APPLICATION LOGIC ---
class ForensicToolApp:
    def __init__(self, root):
        self.root = root; self.root.title("Digital Forensics Tool"); self.root.geometry("800x600"); self.root.configure(bg=THEME["root_bg"]);
        try: self.root.eval('tk::PlaceWindow . center')
        except tkinter.TclError: print("Could not center window.")
        icon_path = os.path.join('assets', 'logo.ico');
        try: self.root.iconbitmap(icon_path)
        except tkinter.TclError: print(f"Warning: Could not find icon file at '{icon_path}'.")
        self.malicious_hashes = malware_scanner.load_malicious_hashes("malicious_hashes.txt"); self.compiled_rules = malware_scanner.compile_rules(malware_scanner.YARA_RULES_PATH)
        if not self.compiled_rules: messagebox.showerror("YARA Rules Error", "Could not load or compile YARA rules.")
        self.setup_ui()

    def setup_ui(self):
        main_frame = tkinter.Frame(self.root, bg=THEME["root_bg"], padx=20, pady=20); main_frame.pack(fill='both', expand=True)
        button_frame = tkinter.Frame(main_frame, bg=THEME["root_bg"]); button_frame.pack(fill='x', pady=(0, 20))
        # Now 3 columns, each with equal weight
        button_frame.grid_columnconfigure((0, 1, 2), weight=1)

        scan_file_button = RoundedButton(button_frame, text="Scan File", command=self.run_file_scan, height=40)
        scan_file_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        # --- NEW: Scan Directory Button ---
        scan_dir_button = RoundedButton(button_frame, text="Scan Directory", command=self.run_directory_scan, height=40)
        scan_dir_button.grid(row=0, column=1, sticky="ew", padx=5)

        extract_button = RoundedButton(button_frame, text="Extract Metadata", command=self.run_extraction, height=40)
        extract_button.grid(row=0, column=2, sticky="ew", padx=(5, 0))
        
        # Treeview setup remains the same
        style = ttk.Style(); style.theme_use("default"); style.configure("Treeview", background=THEME["widget_bg"], foreground=THEME["text_fg"], fieldbackground=THEME["widget_bg"], rowheight=25, font=(THEME["font_family"], THEME["font_size"])); style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})]); style.configure("Treeview.Heading", background=THEME["tree_heading_bg"], foreground=THEME["tree_heading_fg"], font=(THEME["font_family"], THEME["font_size"], "bold"), relief="flat"); style.map("Treeview.Heading", background=[('active', THEME["button_hover_bg"])]); tree_frame = tkinter.Frame(main_frame); tree_frame.pack(fill='both', expand=True); self.results_tree = ttk.Treeview(tree_frame, columns=("Property", "Value"), show="headings"); self.results_tree.heading("Property", text="Property"); self.results_tree.heading("Value", text="Value"); self.results_tree.column("Property", width=250, anchor="w"); self.results_tree.column("Value", anchor="w"); scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.results_tree.yview); self.results_tree.configure(yscrollcommand=scrollbar.set); scrollbar.pack(side="right", fill="y"); self.results_tree.pack(side="left", fill="both", expand=True)

    def update_results_table(self, data):
        for item in self.results_tree.get_children(): self.results_tree.delete(item)
        if 'error' in data: self.results_tree.insert("", "end", values=("Error", data['error']))
        else: self._populate_tree(data)

    def _populate_tree(self, data, parent=""):
        for key, value in data.items():
            key_name = key.replace("_", " ").title()
            if key_name == "Malicious Files" and isinstance(value, list):
                # Special handling for the list of malicious files
                parent_id = self.results_tree.insert(parent, "end", values=(f"▼ {key_name}", f"({len(value)} found)"))
                for file_result in value:
                    # Show the file path as a sub-item
                    file_node = self.results_tree.insert(parent_id, "end", values=(f"  - {os.path.basename(file_result['file_path'])}", file_result['status_message']))
                    # Add detailed findings as children of the file path
                    self._populate_tree({k: v for k, v in file_result.items() if k != 'file_path' and v}, parent=file_node)
            elif isinstance(value, dict):
                item_id = self.results_tree.insert(parent, "end", values=(f"▼ {key_name}", ""))
                self._populate_tree(value, parent=item_id)
            elif isinstance(value, list):
                item_id = self.results_tree.insert(parent, "end", values=(f"▼ {key_name}", f"({len(value)} items)"))
                for i, item in enumerate(value): self.results_tree.insert(item_id, "end", values=(f"  [{i}]", item))
            else:
                self.results_tree.insert(parent, "end", values=(key_name, value))

    def run_file_scan(self):
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path: return
        try:
            results = malware_scanner.scan_file(file_path, self.compiled_rules, self.malicious_hashes)
            self.update_results_table(results)
            if results.get('is_malicious'): messagebox.showwarning("Threat Detected", f"A potential threat was found in:\n{file_path}")
            else: messagebox.showinfo("Scan Complete", f"No threats were detected in:\n{file_path}")
        except Exception as e: self.update_results_table({"Error": str(e)})

    # --- Directory Scan Function ---
    def run_directory_scan(self):
        directory_path = filedialog.askdirectory(title="Select a directory to scan")
        if not directory_path: return
        
        # Show a "please wait" message
        messagebox.showinfo("Scan in Progress", f"Scanning directory:\n{directory_path}\n\nThis may take some time. Please wait for the completion message.")
        self.root.update_idletasks() # Update UI to show the messagebox
        
        try:
            # Call the new scanner function
            scan_report = malware_scanner.scan_directory(directory_path, self.compiled_rules, self.malicious_hashes)
            
            # Update the table with the full report
            self.update_results_table(scan_report)
            
            # Final message
            threats_found = scan_report["scan_summary"]["malicious_files_found"]
            if threats_found > 0:
                messagebox.showwarning("Scan Complete", f"Scan finished. Found {threats_found} potential threat(s). See table for details.")
            else:
                messagebox.showinfo("Scan Complete", "Scan finished. No threats were detected.")

        except Exception as e:
            self.update_results_table({"Error": str(e)})

    def run_extraction(self):
        file_path = filedialog.askopenfilename(title="Select a file to extract metadata")
        if not file_path: return
        try:
            metadata = metadata_extractor.extract_metadata(file_path)
            self.update_results_table(metadata)
        except Exception as e: self.update_results_table({"Error": str(e)})

if __name__ == "__main__":
    root = tkinter.Tk()
    app = ForensicToolApp(root)
    root.mainloop()