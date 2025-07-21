import tkinter
from tkinter import filedialog, messagebox, scrolledtext
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
    "font_family": "Segoe UI",
    "font_size": 10,
    "border_radius": 10
}

# --- CUSTOM WIDGET: RoundedButton ---
class RoundedButton(tkinter.Canvas):
    def __init__(self, parent, text, command, **kwargs):
        # Store colors and styles
        self.bg_color = kwargs.pop("bg", THEME["widget_bg"])
        self.fg_color = kwargs.pop("fg", THEME["text_fg"])
        self.hover_color = kwargs.pop("hover_color", THEME["button_hover_bg"])
        self.active_color = kwargs.pop("active_color", THEME["button_active_bg"])
        self.font = kwargs.pop("font", (THEME["font_family"], THEME["font_size"], "bold"))
        self.radius = kwargs.pop("radius", THEME["border_radius"])
        
        # Initialize the Canvas
        super().__init__(parent, highlightthickness=0, **kwargs)
        
        # This makes the corners transparent to the window background.
        self.configure(bg=parent.cget("bg"))
        
        self.command = command
        self.text = text
        self._state = "normal" # Keep track of the current color state

        # Bind events
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.bind("<ButtonRelease-1>", self._on_release)
        
        # This ensures the button is drawn only after its size is known.
        self.bind("<Configure>", self._on_resize)

    def draw(self, color):
        """Draws the button shape and text with a specific color."""
        self.delete("all")
        width = self.winfo_width()
        height = self.winfo_height()
        
        # Ensure there's a size before trying to draw
        if width <= 1 or height <= 1:
            return

        radius = min(self.radius, width/2, height/2)
        bg = color

        # Create a rounded rectangle shape
        self.create_polygon(
            (radius, 0, width-radius, 0, width, radius, width, height-radius, 
             width-radius, height, radius, height, 0, height-radius, 0, radius),
            fill=bg,
            #smooth=True # This helps create the rounded effect
        )
        
        # Add the text
        self.create_text(width/2, height/2, text=self.text, font=self.font, fill=self.fg_color)

    def _on_resize(self, event):
        """Redraw the button whenever the window is resized."""
        if self._state == "hover":
            self.draw(color=self.hover_color)
        elif self._state == "active":
            self.draw(color=self.active_color)
        else:
            self.draw(color=self.bg_color)

    def _on_enter(self, event):
        self._state = "hover"
        self.draw(color=self.hover_color)

    def _on_leave(self, event):
        self._state = "normal"
        self.draw(color=self.bg_color)

    def _on_click(self, event):
        self._state = "active"
        self.draw(color=self.active_color)

    def _on_release(self, event):
        if 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
            self._state = "hover"
            self.draw(color=self.hover_color)
            if self.command:
                self.command()
        else:
            self._state = "normal"
            self.draw(color=self.bg_color)

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
        """Creates and positions all widgets using our custom button."""
        main_frame = tkinter.Frame(self.root, bg=THEME["root_bg"], padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)

        button_frame = tkinter.Frame(main_frame, bg=THEME["root_bg"])
        button_frame.pack(fill='x', pady=(0, 20))
        button_frame.grid_columnconfigure((0, 1), weight=1)

        scan_button = RoundedButton(button_frame, text="Scan File", command=self.run_scan, height=40)
        scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        extract_button = RoundedButton(button_frame, text="Extract Metadata", command=self.run_extraction, height=40)
        extract_button.grid(row=0, column=1, sticky="ew", padx=(10, 0))

        self.results_text = scrolledtext.ScrolledText(
            main_frame, wrap='word', height=20, bg=THEME["widget_bg"], fg=THEME["text_fg"],
            font=(THEME["font_family"], THEME["font_size"]), relief="flat", borderwidth=0,
            insertbackground=THEME["cursor_color"]
        )
        self.results_text.pack(fill='both', expand=True)
        self.results_text.config(state='disabled')

    def update_results_text(self, content):
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, 'end')
        self.results_text.insert('end', content)
        self.results_text.config(state='disabled')

    def run_scan(self):
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path: return
        try:
            results = malware_scanner.scan_file(file_path, self.compiled_rules, self.malicious_hashes)
            output_content = f"--- SCAN RESULTS FOR: {os.path.basename(results['file_path'])} ---\n\n"
            output_content += f"SHA-256 Hash: {results['file_hash']}\n\n"
            output_content += f"Status: {results['status_message']}\n"
            if results['is_malicious']:
                if results['hash_match']:
                    output_content += "Reason: Matched a known malicious hash.\n"
                if results['yara_matches']:
                    output_content += "\nMatching YARA Rules:\n"
                    for rule in results['yara_matches']:
                        output_content += f"  - {rule}\n"
                messagebox.showwarning("Threat Detected", f"A potential threat was found in:\n{file_path}")
            else:
                messagebox.showinfo("Scan Complete", f"No threats were detected in:\n{file_path}")
            self.update_results_text(output_content)
        except Exception as e:
            error_message = f"An unexpected error occurred during the scan: {str(e)}"
            messagebox.showerror("Error", error_message)
            self.update_results_text(error_message)

    def run_extraction(self):
        file_path = filedialog.askopenfilename(title="Select a file to extract metadata")
        if not file_path: return
        try:
            metadata = metadata_extractor.extract_metadata(file_path)
            output_content = f"--- METADATA FOR: {os.path.basename(file_path)} ---\n\n"
            if 'error' in metadata:
                messagebox.showerror("Extraction Error", metadata['error'])
                output_content += f"Error: {metadata['error']}"
            else:
                for key, value in metadata.items():
                    if isinstance(value, dict):
                        output_content += f"{key.replace('_', ' ').title()}:\n"
                        for sub_key, sub_value in value.items():
                            output_content += f"  - {sub_key.replace('_', ' ').title()}: {sub_value}\n"
                    else:
                        output_content += f"{key.replace('_', ' ').title()}: {value}\n"
            self.update_results_text(output_content)
        except Exception as e:
            error_message = f"An unexpected error occurred during metadata extraction: {str(e)}"
            messagebox.showerror("Error", error_message)
            self.update_results_text(error_message)

# --- Main Execution ---
if __name__ == "__main__":
    root = tkinter.Tk()
    app = ForensicToolApp(root)
    root.mainloop()