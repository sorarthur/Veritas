import tkinter
from tkinter import filedialog, messagebox, scrolledtext
import malware_scanner
import metadata_extractor

# --- Logic Functions ---
def select_file():
    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("All files", "*.*"), ("Images", "*.png;*.jpg;*.jpeg;*.gif"), ("PDFs", "*.pdf"), ("Text files", "*.txt")],
    )

def run_scan():
    file_path = filedialog.askopenfilename(
        title="Select a file to scan",
        filetypes=[("All files", "*.*"), ("Images", "*.png;*.jpg;*.jpeg;*.gif"), ("PDFs", "*.pdf"), ("Text files", "*.txt")],
    )
    if not file_path:
        messagebox.showwarning("No file selected", "Please select a file to scan.")
        return
    try:
        result = malware_scanner.scanner(
            file_path,
            malware_scanner.load_malicious_hashes("malicious_hashes.txt"),
            "rules/yara-rules-core.yar"
        )
        if result[0][0].startswith("Malicious"):
            messagebox.showwarning("Malicious File Detected", result[0][0].format(file_path=file_path, file_hash=result[0][1]))
            results_text.delete(1.0, tkinter.END)
            results_text.insert(tkinter.END, result[0][0].format(file_path=file_path, file_hash=result[0][1]))
        else:
            results_text.delete(1.0, tkinter.END)
            results_text.insert(tkinter.END, result[0][0].format(file_path=file_path, file_hash=result[0][1]))
            if result[1]:
                results_text.insert(tkinter.END, f"\nYARA MATCH - {result[1]}")
            else:
                results_text.insert(tkinter.END, "\nNo YARA rules provided for scanning.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during scanning: {str(e)}")
    
def run_extraction():
    file_path = filedialog.askopenfilename(
        title="Select a file to extract metadata",
        filetypes=[("All files", "*.*"), ("Images", "*.png;*.jpg;*.jpeg;*.gif"), ("PDFs", "*.pdf")],
    )
    if not file_path:
        messagebox.showwarning("No file selected", "Please select a file to extract metadata.")
        return
    try:
        metadata = metadata_extractor.extract_metadata(file_path)
        if 'error' in metadata:
            messagebox.showerror("Error", f"An error occurred: {metadata['error']}")
        else:
            results_text.delete(1.0, tkinter.END)
            results_text.insert(tkinter.END, str(metadata))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during metadata extraction: {str(e)}")
        
# ---- UI Functions ----

root = tkinter.Tk()
root.title("Digital Forensics Tool")
root.geometry("700x500")

# Widgets
top_frame = tkinter.Frame(root)
top_frame.pack(pady=10)

# File Selection Button
# Scan Button
scan_button = tkinter.Button(top_frame, text="Scan File", command=run_scan)
scan_button.pack(side=tkinter.LEFT, padx=5)

# Extract Metadata Button
extract_button = tkinter.Button(top_frame, text="Extract Metadata", command=run_extraction)
extract_button.pack(side=tkinter.LEFT, padx=5)

# Results
results_text = scrolledtext.ScrolledText(root, wrap=tkinter.WORD, width=80, height=20)
results_text.pack(padx=10, pady=10)

# Run the UI
root.mainloop()