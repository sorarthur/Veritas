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
        self.root = root
        self.root.title("Digital Forensics Tool")
        self.root.geometry("800x600")
        self.root.configure(bg=THEME["root_bg"])
        try:
            self.root.eval('tk::PlaceWindow . center')
        except tkinter.TclError:
            print("Could not center window.")
        icon_path = os.path.join('assets', 'logo.ico')
        try:
            self.root.iconbitmap(icon_path)
        except tkinter.TclError:
            print(f"Warning: Could not find icon file at '{icon_path}'.")
        self.malicious_hashes = malware_scanner.load_malicious_hashes("malicious_hashes.txt")
        self.compiled_rules = malware_scanner.compile_rules(malware_scanner.YARA_RULES_PATH)
        if not self.compiled_rules:
            messagebox.showerror("YARA Rules Error", "Could not load or compile YARA rules.")
        self.setup_ui()

    def setup_ui(self):
        """Creates and positions all widgets, now using a Treeview for results."""
        main_frame = tkinter.Frame(self.root, bg=THEME["root_bg"], padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)

        button_frame = tkinter.Frame(main_frame, bg=THEME["root_bg"])
        button_frame.pack(fill='x', pady=(0, 20))
        button_frame.grid_columnconfigure((0, 1), weight=1)

        scan_button = RoundedButton(button_frame, text="Scan File", command=self.run_scan, height=40)
        scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        extract_button = RoundedButton(button_frame, text="Extract Metadata", command=self.run_extraction, height=40)
        extract_button.grid(row=0, column=1, sticky="ew", padx=(10, 0))

        # --- Treeview Table Setup ---
        # Create a style object to theme the treeview
        style = ttk.Style()
        style.theme_use("default") # Start from a basic theme
        
        # Configure the Treeview style
        style.configure("Treeview",
                        background=THEME["widget_bg"],
                        foreground=THEME["text_fg"],
                        fieldbackground=THEME["widget_bg"],
                        rowheight=25,
                        font=(THEME["font_family"], THEME["font_size"]))
        # Remove borders
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])

        # Configure the Heading style
        style.configure("Treeview.Heading",
                        background=THEME["tree_heading_bg"],
                        foreground=THEME["tree_heading_fg"],
                        font=(THEME["font_family"], THEME["font_size"], "bold"),
                        relief="flat")
        
        # Change heading style on mouse hover
        style.map("Treeview.Heading", background=[('active', THEME["button_hover_bg"])])

        # Create a frame for the treeview and its scrollbar
        tree_frame = tkinter.Frame(main_frame)
        tree_frame.pack(fill='both', expand=True)

        # Create the Treeview widget
        self.results_tree = ttk.Treeview(tree_frame, columns=("Property", "Value"), show="headings")
        self.results_tree.heading("Property", text="Property")
        self.results_tree.heading("Value", text="Value")
        self.results_tree.column("Property", width=200, anchor="w")
        self.results_tree.column("Value", anchor="w")
        
        # Create a scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the widgets
        scrollbar.pack(side="right", fill="y")
        self.results_tree.pack(side="left", fill="both", expand=True)

    def update_results_table(self, metadata):
        """Clears and populates the results table with new data."""
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Populate with new data
        if 'error' in metadata:
            self.results_tree.insert("", "end", values=("Error", metadata['error']))
        else:
            self._populate_tree(metadata)

    def _populate_tree(self, data, parent=""):
        """Recursively populates the tree, handling nested dictionaries."""
        for key, value in data.items():
            key_name = key.replace("_", " ").title()
            
            if isinstance(value, dict):
                # Insert the parent key (e.g., "Geolocation") and get its ID
                item_id = self.results_tree.insert(parent, "end", values=(f"▼ {key_name}", ""))
                # Recursively call this function for the nested dictionary
                self._populate_tree(value, parent=item_id)
            elif isinstance(value, list):
                item_id = self.results_tree.insert(parent, "end", values=(f"▼ {key_name}", f"({len(value)} items)"))
                for i, item in enumerate(value):
                    self.results_tree.insert(item_id, "end", values=(f"  [{i}]", item))
            else:
                self.results_tree.insert(parent, "end", values=(key_name, value))

    def run_scan(self):
        # A simple scan result is still needed for the table
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path: return
        try:
            results = malware_scanner.scan_file(file_path, self.compiled_rules, self.malicious_hashes)
            self.update_results_table(results) # Display results in the table
            if results.get('is_malicious'):
                 messagebox.showwarning("Threat Detected", f"A potential threat was found in:\n{file_path}")
            else:
                 messagebox.showinfo("Scan Complete", f"No threats were detected in:\n{file_path}")
        except Exception as e:
            self.update_results_table({"Error": str(e)})

    def run_extraction(self):
        file_path = filedialog.askopenfilename(title="Select a file to extract metadata")
        if not file_path: return
        try:
            metadata = metadata_extractor.extract_metadata(file_path)
            self.update_results_table(metadata) # Populate the table
        except Exception as e:
            self.update_results_table({"Error": str(e)})

# --- Main Execution ---
if __name__ == "__main__":
    root = tkinter.Tk()
    app = ForensicToolApp(root)
    root.mainloop()