import tkinter
from tkinter import filedialog, messagebox, scrolledtext
import malware_scanner
import metadata_extractor

# --- UI LOGIC AND APPLICATION STATE ---

class ForensicToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Tool")
        self.root.geometry("700x500")

        # --- Load resources on startup for efficiency ---
        self.malicious_hashes = malware_scanner.load_malicious_hashes("malicious_hashes.txt")
        self.compiled_rules = malware_scanner.compile_rules(malware_scanner.YARA_RULES_PATH)
        
        # Notify user if rules failed to compile
        if not self.compiled_rules:
            messagebox.showerror(
                "YARA Rules Error",
                f"Could not load or compile YARA rules from:\n{malware_scanner.YARA_RULES_PATH}\n\nYARA scanning will be disabled."
            )

        self.setup_ui()

    def setup_ui(self):
        """Creates and places all the UI widgets."""
        top_frame = tkinter.Frame(self.root)
        top_frame.pack(pady=10)

        scan_button = tkinter.Button(top_frame, text="Scan File", command=self.run_scan, width=20, height=2)
        scan_button.pack(side=tkinter.LEFT, padx=10)

        extract_button = tkinter.Button(top_frame, text="Extract Metadata", command=self.run_extraction, width=20, height=2)
        extract_button.pack(side=tkinter.LEFT, padx=10)

        self.results_text = scrolledtext.ScrolledText(self.root, wrap=tkinter.WORD, width=80, height=20, state='disabled')
        self.results_text.pack(padx=10, pady=10, fill="both", expand=True)

    def update_results_text(self, content):
        """Helper function to safely update the text widget."""
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tkinter.END)
        self.results_text.insert(tkinter.END, content)
        self.results_text.config(state='disabled')

    def run_scan(self):
        """Handles the file scanning process."""
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path:
            return # User cancelled the dialog

        try:
            # *** CORRECTION: Pass the loaded hashes and compiled rules ***
            results = malware_scanner.scan_file(file_path, self.compiled_rules, self.malicious_hashes)
            
            # Prepare the output string
            output_content = f"--- SCAN RESULTS FOR: {results['file_path']} ---\n\n"
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
            return # User cancelled the dialog
            
        try:
            metadata = metadata_extractor.extract_metadata(file_path)
            
            output_content = f"--- METADATA FOR: {file_path} ---\n\n"
            if 'error' in metadata:
                messagebox.showerror("Extraction Error", metadata['error'])
                output_content += f"Error: {metadata['error']}"
            else:
                for key, value in metadata.items():
                    output_content += f"{key}: {value}\n"
            
            self.update_results_text(output_content)

        except Exception as e:
            error_message = f"An unexpected error occurred during metadata extraction: {str(e)}"
            messagebox.showerror("Error", error_message)
            self.update_results_text(error_message)

# --- Main Application Execution ---
if __name__ == "__main__":
    root = tkinter.Tk()
    app = ForensicToolApp(root)
    root.mainloop()