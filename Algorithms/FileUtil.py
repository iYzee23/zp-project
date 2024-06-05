import tkinter as tk
from tkinter import filedialog
import base64


class FileUtil:
    @staticmethod
    def import_message():
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt")],
            title="Open file containing message"
        )

        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                file.close()
                print(f"File is loaded from: {file_path}")
                return content

        return None

    @staticmethod
    def export_message(data):
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save file as: "
        )

        if file_path:
            with open(file_path, 'w') as file:
                file.write(data)
                file.close()
            print(f"File is saved at: {file_path}")

    @staticmethod
    def import_pem(pem_type):
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem")],
            title="Open .pem file"
        )

        if file_path:
            with open(file_path, 'r') as file:
                pem_content = file.read()
                start = f"-----BEGIN {pem_type}-----\n"
                end = f"-----END {pem_type}-----\n"
                pem_content = pem_content.replace(start, "").replace(end, "").strip()
                base64_data = pem_content.encode("utf-8")
                byte_data = base64.b64decode(base64_data)
                content = byte_data.decode("utf-8")
                print(f"File is loaded from: {file_path}")
                return content

        return None

    @staticmethod
    def export_pem(data, pem_type):
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem")],
            title="Save file as: "
        )

        if file_path:
            with open(file_path, 'w') as file:
                byte_data = data.encode("utf-8")
                base64_data = base64.b64encode(byte_data)
                content = base64_data.decode("utf-8")
                start = f"-----BEGIN {pem_type}-----\n"
                end = f"-----END {pem_type}-----\n"
                pem_content = f"{start}{content}\n{end}"
                file.write(pem_content)
            print(f"File is saved at: {file_path}")
