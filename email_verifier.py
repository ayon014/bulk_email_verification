import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import pandas as pd
import requests
import csv
import os

API_KEY = "f4488df31e8e4cf70b779feb674c23f146adf30d23f3923503b4584bfe6b"
MAX_FREE_EMAILS = 100  # Free plan limit

class EmailValidatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bulk Email Validator")
        self.root.geometry("750x600")
        self.root.resizable(True, True)
        self.setup_ui()
        
    def setup_ui(self):
        # File selection
        ttk.Label(self.root, text="Select CSV or Excel file with emails:").pack(pady=5)
        self.file_path_var = tk.StringVar()
        ttk.Entry(self.root, textvariable=self.file_path_var, width=70, state="readonly").pack(pady=5)
        ttk.Button(self.root, text="Browse File", command=self.browse_file).pack(pady=5)

        # Validate button
        ttk.Button(self.root, text="Validate Emails", command=self.validate_emails).pack(pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(self.root, mode='determinate', length=600)
        self.progress.pack(pady=5)

        # Log area
        ttk.Label(self.root, text="Validation Log:").pack(pady=5)
        self.log_text = scrolledtext.ScrolledText(self.root, width=85, height=25)
        self.log_text.pack(pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("CSV or Excel files", "*.csv *.xlsx *.xls"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def read_emails(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            df = pd.read_csv(file_path)
        elif ext in [".xlsx", ".xls"]:
            df = pd.read_excel(file_path)
        else:
            raise ValueError("Unsupported file type.")
        
        # Try to detect email column
        email_col = next((col for col in df.columns if "email" in col.lower()), df.columns[0])
        emails = df[email_col].dropna().astype(str).tolist()
        return emails[:MAX_FREE_EMAILS]

    def validate_email(self, email):
        url = f"https://api.quickemailverification.com/v1/verify?email={email}&apikey={API_KEY}"
        try:
            resp = requests.get(url, timeout=20)
            data = resp.json()
            return data.get("result", "unknown"), data.get("reason", "")
        except Exception as e:
            return "error", str(e)

    def save_results(self, results):
        valid = [e for e, (s, _) in results.items() if s == "valid"]
        invalid = [e for e, (s, _) in results.items() if s != "valid"]

        with open("valid_emails.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Email", "Status"])
            for e in valid:
                writer.writerow([e, "valid"])
        
        with open("invalid_emails.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Email", "Status", "Reason"])
            for e in invalid:
                status, reason = results[e]
                writer.writerow([e, status, reason])
        
        return len(valid), len(invalid)

    def validate_emails(self):
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
        
        try:
            emails = self.read_emails(file_path)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        if not emails:
            messagebox.showwarning("Warning", "No emails found")
            return

        self.log_text.delete(1.0, tk.END)
        self.log(f"Processing {len(emails)} emails...")
        self.progress['maximum'] = len(emails)
        self.progress['value'] = 0

        results = {}
        for i, email in enumerate(emails, 1):
            status, reason = self.validate_email(email)
            results[email] = (status, reason)
            self.log(f"{i}. {email} -> {status} ({reason})")
            self.progress['value'] = i
            self.root.update_idletasks()
            self.root.after(100)

        valid_count, invalid_count = self.save_results(results)
        self.log(f"Validation complete! Valid: {valid_count}, Invalid: {invalid_count}")
        messagebox.showinfo("Done", f"Validation complete!\nValid: {valid_count}\nInvalid: {invalid_count}\nFiles saved as valid_emails.csv and invalid_emails.csv")

def main():
    root = tk.Tk()
    app = EmailValidatorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
