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

def send_email(smtp_details, from_email, to_emails, subject, body, attachment_path=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = ", ".join(to_emails)
        msg['Subject'] = subject

        if body.strip().startswith("<html>"):
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))

        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
                msg.attach(part)

        with smtplib.SMTP(smtp_details['host'], smtp_details['port']) as server:
            server.starttls()
            server.login(smtp_details['user'], smtp_details['password'])
            server.sendmail(from_email, to_emails, msg.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email to {to_emails}: {e}")
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
    body = body_text.get("1.0", tk.END).strip()
    attachment_path = attachment_label.cget("text")

    if not smtp_accounts or not emails or not subject or not body:
        messagebox.showerror("Error", "Please fill all fields!")
        return

    send_button.config(state=tk.DISABLED)
    progress_bar['value'] = 0
    progress_bar['maximum'] = len(emails)

    batch_size = 1000
    email_batches = [emails[i:i + batch_size] for i in range(0, len(emails), batch_size)]

    def send_emails_thread():
        for batch in email_batches:
            smtp = smtp_accounts[len(email_batches) % len(smtp_accounts)]
            success = send_email(smtp, smtp['user'], batch, subject, body, attachment_path)
            if success:
                progress_bar['value'] += len(batch)
                root.update_idletasks()
        messagebox.showinfo("Success", "All emails sent successfully!")
        send_button.config(state=tk.NORMAL)

    threading.Thread(target=send_emails_thread).start()

def attach_file():
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    if file_path:
        attachment_label.config(text=file_path)

def on_resize(event):
    for widget in [email_list, subject_entry, body_text]:
        widget.config(width=event.width)

root = tk.Tk()
root.title("Email Sending System")
root.geometry("600x500")  # Reduced size for small devices
root.resizable(True, True)
root.bind("<Configure>", on_resize)

style = ThemedStyle(root)
style.set_theme("arc")

smtp_frame = tk.LabelFrame(root, text="SMTP Accounts", padx=10, pady=10)
smtp_frame.pack(fill=tk.X, padx=10, pady=5)

smtp_entries = []
add_smtp_button = tk.Button(smtp_frame, text="Add SMTP")
add_smtp_button.pack(pady=5)

email_frame = tk.LabelFrame(root, text="Recipient Emails", padx=10, pady=10)
email_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
email_list = tk.Text(email_frame, height=5)  # Reduced height
email_list.pack(fill=tk.BOTH, expand=True)

subject_frame = tk.LabelFrame(root, text="Subject", padx=10, pady=10)
subject_frame.pack(fill=tk.X, padx=10, pady=5)
subject_entry = tk.Entry(subject_frame)
subject_entry.pack(fill=tk.X)

body_frame = tk.LabelFrame(root, text="Email Body", padx=10, pady=10)
body_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
body_text = tk.Text(body_frame, height=5)  # Reduced height
body_text.pack(fill=tk.BOTH, expand=True)

attachment_frame = tk.LabelFrame(root, text="Attachment", padx=10, pady=10)
attachment_frame.pack(fill=tk.X, padx=10, pady=5)
attachment_label = tk.Label(attachment_frame, text="No file selected", fg="gray")
attachment_label.pack(side=tk.LEFT, padx=5)
attach_button = tk.Button(attachment_frame, text="Attach File", command=attach_file)
attach_button.pack(side=tk.RIGHT)

progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, mode="determinate")
progress_bar.pack(fill=tk.X, padx=10, pady=5)

send_button = tk.Button(root, text="Send Emails", command=distribute_emails)
send_button.pack(fill=tk.X, padx=10, pady=5)

root.mainloop()