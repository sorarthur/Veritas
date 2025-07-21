import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from ttkbootstrap.scrolled import ScrolledText
import malware_scanner
import metadata_extractor
import os

# --- UI LOGIC AND APPLICATION STATE ---

class ForensicToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Tool")
        self.root.geometry("800x600")
        self.root.eval('tk::PlaceWindow . center')

        icon_path = os.path.join('assets', 'logo.ico')
        try:
            self.root.iconbitmap(icon_path)
        except ttk.TclError:
            print(f"Warning: Could not find icon file at '{icon_path}'. Using default icon.")

        self.malicious_hashes = malware_scanner.load_malicious_hashes("malicious_hashes.txt")
        self.compiled_rules = malware_scanner.compile_rules(malware_scanner.YARA_RULES_PATH)

        if not self.compiled_rules:
            messagebox.showerror(
                "YARA Rules Error",
                f"Could not load or compile YARA rules from:\n{malware_scanner.YARA_RULES_PATH}\n\nYARA scanning will be disabled."
            )

        self.setup_ui()

    def setup_ui(self):
        """Creates and places all the UI widgets using ttk widgets."""
        main_frame = ttk.Frame(self.root, padding="20 20 20 20")
        main_frame.pack(fill=BOTH, expand=YES)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=X, pady=(0, 20))

        scan_button = ttk.Button(button_frame, text="Scan File", command=self.run_scan, bootstyle="outline")
        scan_button.pack(side=LEFT, fill=X, expand=YES, padx=(0, 10))

        extract_button = ttk.Button(button_frame, text="Extract Metadata", command=self.run_extraction, bootstyle="outline")
        extract_button.pack(side=LEFT, fill=X, expand=YES, padx=(10, 0))

        self.results_text = ScrolledText(main_frame, wrap=WORD, height=20, autohide=True)
        self.results_text.pack(fill=BOTH, expand=YES)
        
        # *** CORRECTION 1: Use the .state() method to disable ***
        self.results_text.state(['disabled'])

    def update_results_text(self, content):
        """Helper function to safely update the text widget."""
        # *** CORRECTION 2: Use the .state() method to enable ***
        self.results_text.state(['!disabled']) # Note the '!' for "not disabled"
        
        self.results_text.delete(1.0, END)
        self.results_text.insert(END, content)
        
        # *** CORRECTION 3: Use the .state() method to disable again ***
        self.results_text.state(['disabled'])

    # The logic for run_scan and run_extraction remains exactly the same
    def run_scan(self):
        """Handles the file scanning process."""
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path:
            return

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
        """Handles the metadata extraction process."""
        file_path = filedialog.askopenfilename(title="Select a file to extract metadata")
        if not file_path:
            return

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

# --- Main Application Execution ---
if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")
    app = ForensicToolApp(root)
    root.mainloop()