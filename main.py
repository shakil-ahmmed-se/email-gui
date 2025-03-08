import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from ttkthemes import ThemedStyle
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import threading
import os
import pdfkit  # For converting HTML to PDF
import sys
import logging
from datetime import datetime

# Helper function for PyInstaller compatibility
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Custom handler to display logs in the Tkinter Text widget
class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.see(tk.END)  # Auto-scroll to the latest log
        self.text_widget.configure(state='disabled')

def send_email(smtp_details, from_email, to_email, subject, plain_body, html_body=None, attachment_path=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email  # Single recipient
        msg['Subject'] = subject

        msg.attach(MIMEText(plain_body, 'plain'))

        if html_body and html_body.strip():
            pdf_path = resource_path("temp_email_body.pdf")
            pdfkit.from_string(html_body, pdf_path)
            with open(pdf_path, "rb") as pdf_file:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(pdf_file.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename=email_body.pdf')
                msg.attach(part)
            if os.path.exists(pdf_path):
                os.remove(pdf_path)

        if attachment_path and os.path.exists(attachment_path) and attachment_path != "No file selected":
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
                msg.attach(part)

        with smtplib.SMTP(smtp_details['host'], smtp_details['port']) as server:
            server.starttls()
            server.login(smtp_details['user'], smtp_details['password'])
            server.sendmail(from_email, [to_email], msg.as_string())
        logger.info(f"Successfully sent email to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def distribute_emails():
    smtp_accounts = [
        {
            'host': smtp['host'].get(),
            'port': int(smtp['port'].get()),
            'user': smtp['user'].get(),
            'password': smtp['password'].get()
        }
        for smtp in smtp_entries
    ]

    emails = email_list.get("1.0", tk.END).strip().splitlines()
    subject = subject_entry.get()
    plain_body = plain_body_text.get("1.0", tk.END).strip()
    html_body = html_body_text.get("1.0", tk.END).strip()
    attachment_path = attachment_label.cget("text")

    if not smtp_accounts or not emails or not subject or not plain_body:
        messagebox.showerror("Error", "Please fill all required fields!")
        return

    send_button.config(state=tk.DISABLED)
    progress_bar['value'] = 0
    progress_bar['maximum'] = len(emails)
    log_text.delete("1.0", tk.END)  # Clear previous logs

    def send_emails_thread():
        smtp_index = 0
        logger.info("Starting email distribution...")
        for email in emails:
            smtp = smtp_accounts[smtp_index % len(smtp_accounts)]
            success = send_email(smtp, smtp['user'], email.strip(), subject, plain_body, html_body, attachment_path)
            if success:
                progress_bar['value'] += 1
                root.update_idletasks()
            smtp_index += 1
        logger.info("Email distribution completed.")
        messagebox.showinfo("Success", "All emails sent successfully!")
        send_button.config(state=tk.NORMAL)

    threading.Thread(target=send_emails_thread).start()

def attach_file():
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    if file_path:
        attachment_label.config(text=file_path)

def remove_attachment():
    attachment_label.config(text="No file selected")

def delete_smtp(entry_dict, frame):
    smtp_entries.remove(entry_dict)
    frame.destroy()
    smtp_canvas.configure(scrollregion=smtp_canvas.bbox("all"))
    if len(smtp_entries) <= 2:
        smtp_scrollbar.pack_forget()

def add_smtp():
    frame = tk.Frame(smtp_inner_frame)
    frame.pack(fill=tk.X, pady=5)

    tk.Label(frame, text="Host:").grid(row=0, column=0, padx=5)
    host_entry = tk.Entry(frame)
    host_entry.grid(row=0, column=1, padx=5)
    host_entry.insert(0, "smtp.gmail.com")

    tk.Label(frame, text="Port:").grid(row=0, column=2, padx=5)
    port_entry = tk.Entry(frame, width=5)
    port_entry.grid(row=0, column=3, padx=5)
    port_entry.insert(0, "587")

    tk.Label(frame, text="Email:").grid(row=0, column=4, padx=5)
    user_entry = tk.Entry(frame)
    user_entry.grid(row=0, column=5, padx=5)

    tk.Label(frame, text="Password:").grid(row=0, column=6, padx=5)
    password_entry = tk.Entry(frame, show="*")
    password_entry.grid(row=0, column=7, padx=5)

    delete_button = tk.Button(frame, text="X", command=lambda: delete_smtp(entry_dict, frame), width=2, fg="red")
    delete_button.grid(row=0, column=8, padx=5)

    entry_dict = {
        'host': host_entry,
        'port': port_entry,
        'user': user_entry,
        'password': password_entry
    }
    smtp_entries.append(entry_dict)

    smtp_canvas.configure(scrollregion=smtp_canvas.bbox("all"))
    if len(smtp_entries) > 2:
        smtp_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Create the main window
root = tk.Tk()
root.title("Email Sending System")
root.geometry("1000x700")  # Increased height for log area
root.resizable(True, True)

# Apply modern theme
style = ThemedStyle(root)
style.set_theme("arc")

# Main frame with two columns
main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Left Column
left_column = tk.Frame(main_frame)
left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

# Right Column
right_column = tk.Frame(main_frame)
right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

# SMTP Accounts Frame with Scrolling
smtp_frame = tk.LabelFrame(left_column, text="SMTP Accounts", padx=10, pady=10)
smtp_frame.pack(fill=tk.BOTH, padx=5, pady=5)

smtp_canvas = tk.Canvas(smtp_frame, height=100)
smtp_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

smtp_scrollbar = ttk.Scrollbar(smtp_frame, orient=tk.VERTICAL, command=smtp_canvas.yview)
smtp_canvas.configure(yscrollcommand=smtp_scrollbar.set)

smtp_inner_frame = tk.Frame(smtp_canvas)
smtp_canvas.create_window((0, 0), window=smtp_inner_frame, anchor="nw")

smtp_entries = []
add_smtp_button = tk.Button(left_column, text="Add SMTP", command=add_smtp)
add_smtp_button.pack(pady=5)

smtp_canvas.bind(
    "<Configure>",
    lambda e: smtp_canvas.configure(scrollregion=smtp_canvas.bbox("all"))
)

# Recipient Emails Frame
email_frame = tk.LabelFrame(left_column, text="Recipient Emails", padx=10, pady=10)
email_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
email_list = tk.Text(email_frame, height=5)
email_list.pack(fill=tk.BOTH, expand=True)

# Subject Frame
subject_frame = tk.LabelFrame(left_column, text="Subject", padx=10, pady=10)
subject_frame.pack(fill=tk.X, padx=5, pady=5)
subject_entry = tk.Entry(subject_frame)
subject_entry.pack(fill=tk.X)

# Plain Text Body Frame
plain_body_frame = tk.LabelFrame(right_column, text="Plain Text Body (Required)", padx=10, pady=10)
plain_body_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
plain_body_text = tk.Text(plain_body_frame, height=5)
plain_body_text.pack(fill=tk.BOTH, expand=True)

# HTML Body Frame
html_body_frame = tk.LabelFrame(right_column, text="HTML Body (Optional - Converts to PDF)", padx=10, pady=10)
html_body_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
html_body_text = tk.Text(html_body_frame, height=5)
html_body_text.pack(fill=tk.BOTH, expand=True)

# Attachment Frame
attachment_frame = tk.LabelFrame(right_column, text="Attachment", padx=10, pady=10)
attachment_frame.pack(fill=tk.X, padx=5, pady=5)
attachment_label = tk.Label(attachment_frame, text="No file selected", fg="gray")
attachment_label.pack(side=tk.LEFT, padx=5)
attach_button = tk.Button(attachment_frame, text="Attach File", command=attach_file)
attach_button.pack(side=tk.RIGHT, padx=5)
remove_button = tk.Button(attachment_frame, text="Remove", command=remove_attachment)
remove_button.pack(side=tk.RIGHT)

# Progress Bar
progress_bar = ttk.Progressbar(right_column, orient=tk.HORIZONTAL, mode="determinate")
progress_bar.pack(fill=tk.X, padx=5, pady=5)

# Send Button
send_button = tk.Button(right_column, text="Send Emails", command=distribute_emails)
send_button.pack(fill=tk.X, padx=5, pady=5)

# Log Frame (below everything)
log_frame = tk.LabelFrame(root, text="Logs", padx=10, pady=10)
log_frame.pack(fill=tk.BOTH, padx=10, pady=5)
log_text = tk.Text(log_frame, height=10, state='disabled')
log_text.pack(fill=tk.BOTH, expand=True)

# Attach the custom handler to the logger
text_handler = TextHandler(log_text)
logger.addHandler(text_handler)

root.mainloop()