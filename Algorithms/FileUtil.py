import tkinter as tk
from tkinter import filedialog
import base64
class FileUtil:

    def import_message(self):
        # Kreiranje glavnog prozora (root)
        root = tk.Tk()
        root.withdraw()  # Sakrivanje glavnog prozora

        # Prikazivanje dijaloga za otvaranje fajla
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt")],  # Jedini podrzani tip fajla je .txt
            title="Open file containing message"
        )
        if file_path:
            # Ako je fajl izabran, moze se ucitati
            with open(file_path, 'r') as file:
                content = file.read()  # Ucitavanje sadrzaja fajla
                file.close()
                print(f"File is loaded from: {file_path}")
                return content
    def export_message(self, data):
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],  # Jedini podrzani tip fajla je .txt
            title="Save file as: "
        )
        if file_path:
            # Ako je fajl izabran, moze se sacuvati
            with open(file_path, 'w') as file:
                file.write(data)
                file.close()
            print(f"File is saved at: {file_path}")
    def import_PEM(self, pem_type):
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem")],  # Jedini podrzani tip fajla je .pem
            title="Open .pem file"
        )
        if file_path:
            # Ako je fajl izabran, moze se ucitati
            with open(file_path, 'r') as file:
                pem_content = file.read()  # Ucitavanje sadrzaja fajla
                start = f"-----BEGIN {pem_type}-----\n"
                end = f"-----END {pem_type}-----\n"
                pem_content = pem_content.replace(start, "").replace(end, "").strip().encode('utf-8')
                content = base64.b64decode(pem_content).decode('utf-8')
                print(f"File is loaded from: {file_path}")
                return content
    def export_PEM(self, data, pem_type):
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem")],  # Jedini podrzani tip fajla je .pem
            title="Save file as: "
        )
        if file_path:
            # Ako je fajl izabran, moze se sacuvati
            with open(file_path, 'w') as file:
                # Base64 enkodovanje binarnog sadržaja
                b64_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
                # Kreiranje PEM strukture
                pem_content = f"-----BEGIN {pem_type}-----\n{b64_data}\n-----END {pem_type}-----\n"
                file.write(pem_content)
            print(f"File is saved at: {file_path}")

