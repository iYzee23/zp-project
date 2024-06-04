import tkinter as tk
from tkinter import ttk, messagebox, filedialog


class GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PGP application")
        self.geometry("660x580")
        self.container = ttk.Frame(self)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        self.error_label = None
        self.pages = {}
        self.create_login_page()
        self.show_page("Login")

    def show_page(self, page_name):
        page = self.pages[page_name]
        page.tkraise()

    def create_login_page(self):
        login_frame = ttk.Frame(self.container)
        login_frame.grid(row=0, column=0, sticky="nsew")
        self.pages["Login"] = login_frame

        header_label = ttk.Label(login_frame, text="Login Page", font=("Helvetica", 20))
        header_label.grid(row=0, column=0, columnspan=2, pady=130, padx=240)

        username_label = ttk.Label(login_frame, text="Name###Email:", font=("Helvetica", 14))
        username_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")

        self.username_entry = ttk.Entry(login_frame, font=("Helvetica", 14))
        self.username_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        style = ttk.Style()
        style.configure("Login.TButton", font=("Helvetica", 14))

        login_button = ttk.Button(login_frame, text="Login", command=self.check_login, style="Login.TButton")
        login_button.grid(row=2, column=0, columnspan=2, pady=20)

    def check_login(self):
        username = self.username_entry.get()
        if self.validate_username(username):
            self.username_entry.delete(0, tk.END)
            if self.error_label:
                self.error_label.destroy()
                self.error_label = None
            self.create_main_application()
            self.show_page("Keys")
        else:
            self.error_label = ttk.Label(
                self.pages["Login"],
                text="Invalid username",
                foreground="red",
                font=("Helvetica", 14)
            )
            self.error_label.grid(row=3, column=0, columnspan=2, pady=5)

    def validate_username(self, username):
        # Placeholder for the logic
        return username == "admin"

    def create_main_application(self):
        self.create_menu()
        self.create_keys_page()
        self.create_private_ring_page()
        self.create_public_ring_page()
        self.create_send_message_page()
        self.create_receive_message_page()

    def create_menu(self):
        menu_bar = tk.Menu(self)
        menu_bar.add_command(label="Keys", command=self.show_keys_page)
        menu_bar.add_command(label="Private Ring", command=self.show_private_ring_page)
        menu_bar.add_command(label="Public Ring", command=self.show_public_ring_page)
        menu_bar.add_command(label="Send Message", command=self.show_send_message_page)
        menu_bar.add_command(label="Receive Message", command=self.show_receive_message_page)
        menu_bar.add_command(label="Logout", command=self.logout)
        self.config(menu=menu_bar)

    def create_keys_page(self):
        keys_frame = ttk.Frame(self.container)
        keys_frame.grid(row=0, column=0, sticky="nsew")
        self.pages["Keys"] = keys_frame

        sections = ["Generate keys", "Import keys", "Export keys", "Delete keys"]
        for idx, section in enumerate(sections):
            section_label = ttk.Label(keys_frame, text=section, font=("Helvetica", 14, "bold"))
            section_label.grid(row=idx * 4, column=0, columnspan=4, pady=(20 if idx == 0 else 10), sticky="w")

        self.create_generate_keys_section(keys_frame)
        self.create_import_keys_section(keys_frame)
        self.create_export_keys_section(keys_frame)
        self.create_delete_keys_section(keys_frame)

        self.status_label = ttk.Label(keys_frame, text="", font=("Helvetica", 12))
        self.status_label.grid(row=17, column=0, columnspan=4, pady=20)

    def create_generate_keys_section(self, parent):
        ttk.Label(parent, text="Key size:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.key_size = ttk.Combobox(parent, values=["1024", "2048"])
        self.key_size.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(parent, text="Email:").grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.email_entry = ttk.Entry(parent)
        self.email_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(parent, text="Name:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.name_entry = ttk.Entry(parent)
        self.name_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(parent, text="Password:").grid(row=2, column=2, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(parent, show="*")
        self.password_entry.grid(row=2, column=3, padx=5, pady=5, sticky="w")

        generate_button = ttk.Button(parent, text="Generate keys", command=self.generate_keys)
        generate_button.grid(row=3, column=0, columnspan=4, pady=10)

    def create_import_keys_section(self, parent):
        import_public_button = ttk.Button(parent, text="Import Public key", command=self.import_public_key)
        import_public_button.grid(row=5, column=0, columnspan=2, pady=10)

        import_both_button = ttk.Button(parent, text="Import Private & Public keys", command=self.import_both_keys)
        import_both_button.grid(row=5, column=2, columnspan=2, pady=10)

    def create_export_keys_section(self, parent):
        self.export_public_selection = ttk.Combobox(parent)
        self.export_public_selection.grid(row=9, column=0, columnspan=2, padx=10, pady=5)

        self.export_both_selection = ttk.Combobox(parent)
        self.export_both_selection.grid(row=9, column=2, columnspan=2, padx=10, pady=5)

        export_public_button = ttk.Button(parent, text="Export Public key", command=self.export_public_key)
        export_public_button.grid(row=10, column=0, columnspan=2, pady=10)

        export_both_button = ttk.Button(parent, text="Export Private & Public keys", command=self.export_both_keys)
        export_both_button.grid(row=10, column=2, columnspan=2, pady=10)

    def create_delete_keys_section(self, parent):
        self.delete_public_selection = ttk.Combobox(parent)
        self.delete_public_selection.grid(row=13, column=0, columnspan=2, padx=10, pady=5)

        self.delete_both_selection = ttk.Combobox(parent)
        self.delete_both_selection.grid(row=13, column=2, columnspan=2, padx=10, pady=5)

        delete_public_button = ttk.Button(parent, text="Delete Public key", command=self.delete_public_key)
        delete_public_button.grid(row=14, column=0, columnspan=2, pady=10)

        delete_both_button = ttk.Button(parent, text="Delete Private & Public keys", command=self.delete_both_keys)
        delete_both_button.grid(row=14, column=2, columnspan=2, pady=10)

    def create_private_ring_page(self):
        private_ring_frame = ttk.Frame(self.container)
        private_ring_frame.grid(row=0, column=0, sticky="nsew")
        self.pages["Private Ring"] = private_ring_frame

        label = ttk.Label(private_ring_frame, text="Private Ring", font=("Helvetica", 14, "bold"))
        label.pack(pady=10)

        scrollable_frame = ttk.Frame(private_ring_frame)
        scrollable_frame.pack(fill="both")

        text_widget = tk.Text(scrollable_frame, wrap="none", height=30, width=60)
        text_widget.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(scrollable_frame, orient="vertical", command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.insert("end", "-" * 80 + "\n")
        for i in range(1, 21):
            text_widget.insert("end", f"Private Ring Entry {i}\n")
            text_widget.insert("end", "-" * 80 + "\n")
        text_widget.configure(state="disabled")

        button_frame = ttk.Frame(private_ring_frame)
        button_frame.pack(pady=10)

        view_button = ttk.Button(button_frame, text="View more details")
        view_button.pack()

    def create_public_ring_page(self):
        public_ring_frame = ttk.Frame(self.container)
        public_ring_frame.grid(row=0, column=0, sticky="nsew")
        self.pages["Public Ring"] = public_ring_frame

        label = ttk.Label(public_ring_frame, text="Public Ring", font=("Helvetica", 14, "bold"))
        label.pack(pady=10)

        scrollable_frame = ttk.Frame(public_ring_frame)
        scrollable_frame.pack(fill="both")

        text_widget = tk.Text(scrollable_frame, wrap="none", height=30, width=60)
        text_widget.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(scrollable_frame, orient="vertical", command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.insert("end", "-" * 80 + "\n")
        for i in range(1, 21):
            text_widget.insert("end", f"Public Ring Entry {i}\n")
            text_widget.insert("end", "-" * 80 + "\n")
        text_widget.configure(state="disabled")

    def create_send_message_page(self):
        send_message_frame = ttk.Frame(self.container)
        send_message_frame.grid(row=0, column=0, sticky="nsew")
        self.pages["Send Message"] = send_message_frame

        send_message_frame.columnconfigure(0, weight=1)
        send_message_frame.columnconfigure(1, weight=1)
        send_message_frame.rowconfigure(2, weight=1)

        style = ttk.Style()
        style.configure("TCheckbutton", font=("Helvetica", 10))

        self.auth_var = tk.BooleanVar()
        self.comp_var = tk.BooleanVar()
        self.enc_var = tk.BooleanVar()
        self.radix_var = tk.BooleanVar()

        checkboxes_frame = ttk.Frame(send_message_frame)
        checkboxes_frame.grid(row=0, column=0, sticky="n", padx=5, pady=5)

        auth_check = ttk.Checkbutton(
            checkboxes_frame,
            text="Authentication",
            variable=self.auth_var,
            command=self.toggle_authentication,
            style="TCheckbutton"
        )
        auth_check.grid(row=0, column=0, sticky="w", pady=2)

        enc_check = ttk.Checkbutton(
            checkboxes_frame,
            text="Encryption",
            variable=self.enc_var,
            command=self.toggle_encryption,
            style="TCheckbutton"
        )
        enc_check.grid(row=1, column=0, sticky="w", pady=2)

        comp_check = ttk.Checkbutton(
            checkboxes_frame,
            text="Compression",
            variable=self.comp_var,
            style="TCheckbutton"
        )
        comp_check.grid(row=2, column=0, sticky="w", pady=2)

        radix_check = ttk.Checkbutton(
            checkboxes_frame,
            text="Radix64",
            variable=self.radix_var,
            style="TCheckbutton"
        )
        radix_check.grid(row=3, column=0, sticky="w", pady=2)

        options_frame = ttk.Frame(send_message_frame)
        options_frame.grid(row=0, column=1, sticky="n", padx=10, pady=5)

        ttk.Label(options_frame, text="Select KeyID for Authentication:").grid(row=0, column=0, sticky="w", pady=3)
        self.auth_keyid_combo = ttk.Combobox(options_frame)
        self.auth_keyid_combo.grid(row=0, column=1, sticky="w", padx=(5, 0), pady=3)
        self.auth_keyid_combo.config(state="disabled")

        ttk.Label(options_frame, text="Select User for Encryption:").grid(row=1, column=0, sticky="w", pady=3)
        self.enc_user_combo = ttk.Combobox(options_frame)
        self.enc_user_combo.grid(row=1, column=1, sticky="w", padx=(5, 0), pady=3)
        self.enc_user_combo.config(state="disabled")

        ttk.Label(options_frame, text="Select KeyID for Encryption:").grid(row=2, column=0, sticky="w", pady=3)
        self.enc_keyid_combo = ttk.Combobox(options_frame)
        self.enc_keyid_combo.grid(row=2, column=1, sticky="w", padx=(5, 0), pady=3)
        self.enc_keyid_combo.config(state="disabled")

        ttk.Label(options_frame, text="Select Algorithm:").grid(row=3, column=0, sticky="w", pady=3)
        self.algorithm_combo = ttk.Combobox(options_frame, values=["AES128", "DES3"])
        self.algorithm_combo.grid(row=3, column=1, sticky="w", padx=(5, 0), pady=3)
        self.algorithm_combo.config(state="disabled")

        ttk.Label(send_message_frame, text="Message:").grid(row=1, column=0, columnspan=2, sticky="w", padx=10)
        self.message_text = tk.Text(send_message_frame, width=80, height=15)
        self.message_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        send_button = ttk.Button(send_message_frame, text="Send Message", command=self.send_message)
        send_button.grid(row=3, column=0, columnspan=2, pady=10)

    def toggle_authentication(self):
        if self.auth_var.get():
            self.auth_keyid_combo.config(state="normal")
        else:
            self.auth_keyid_combo.config(state="disabled")

    def toggle_encryption(self):
        if self.enc_var.get():
            self.enc_user_combo.config(state="normal")
            self.enc_keyid_combo.config(state="normal")
            self.algorithm_combo.config(state="normal")
        else:
            self.enc_user_combo.config(state="disabled")
            self.enc_keyid_combo.config(state="disabled")
            self.algorithm_combo.config(state="disabled")

    def send_message(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as file:
                file.write(self.message_text.get("1.0", tk.END))
            messagebox.showinfo("Success", "Message sent successfully!")

    def create_receive_message_page(self):
        receive_message_frame = ttk.Frame(self.container)
        receive_message_frame.grid(row=0, column=0, sticky="nsew")
        self.pages["Receive Message"] = receive_message_frame

        receive_message_frame.columnconfigure(0, weight=1)
        receive_message_frame.rowconfigure(2, weight=1)

        labels_frame = ttk.Frame(receive_message_frame)
        labels_frame.grid(row=0, column=0, columnspan=2, pady=10)

        self.auth_label = ttk.Label(labels_frame, text="Authentication/signature [option]", font=("Helvetica", 10), foreground="black")
        self.auth_label.grid(row=0, column=0, sticky="w", pady=5)

        self.enc_label = ttk.Label(labels_frame, text="Encryption AES128/DES3 [option]", font=("Helvetica", 10), foreground="black")
        self.enc_label.grid(row=1, column=0, sticky="w", pady=5)

        self.comp_label = ttk.Label(labels_frame, text="Compression [option]", font=("Helvetica", 10), foreground="black")
        self.comp_label.grid(row=2, column=0, sticky="w", pady=5)

        self.radix_label = ttk.Label(labels_frame, text="Radix64 [option]", font=("Helvetica", 10), foreground="black")
        self.radix_label.grid(row=3, column=0, sticky="w", pady=5)

        self.auth_result_label = ttk.Label(labels_frame, text="", font=("Helvetica", 10))
        self.auth_result_label.grid(row=4, column=0, sticky="w", pady=5)

        self.enc_algo_label = ttk.Label(labels_frame, text="", font=("Helvetica", 10))
        self.enc_algo_label.grid(row=5, column=0, sticky="w", pady=5)

        ttk.Label(receive_message_frame, text="Message:").grid(row=1, column=0, columnspan=2, sticky="w", padx=10)
        self.message_text = tk.Text(receive_message_frame, width=80, height=15)
        self.message_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        buttons_frame = ttk.Frame(receive_message_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=10)

        receive_button = ttk.Button(buttons_frame, text="Receive Message", command=self.receive_message)
        receive_button.grid(row=0, column=0, padx=5)

        save_button = ttk.Button(buttons_frame, text="Save Message", command=self.save_message)
        save_button.grid(row=0, column=1, padx=5)

    def receive_message(self):
        message = "This is a received message."
        self.message_text.configure(state="normal")
        self.message_text.delete("1.0", tk.END)
        self.message_text.insert(tk.END, message)
        self.message_text.configure(state="disabled")

        self.auth_label.configure(foreground="blue")
        self.enc_label.configure(foreground="blue")
        self.comp_label.configure(foreground="blue")
        self.radix_label.configure(foreground="blue")

        self.auth_result_label.configure(text="Unsuccessful verification", foreground="red")
        self.enc_algo_label.configure(text="AES128", foreground="green")

    def save_message(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as file:
                file.write(self.message_text.get("1.0", tk.END))
            messagebox.showinfo("Success", "Message saved successfully!")

    def logout(self):
        self.show_page("Login")

    def delete_public_key(self):
        # Placeholder for logic
        self.status_label.config(text="Public key deleted successfully!", foreground="green")

    def delete_both_keys(self):
        # Placeholder for logic
        self.status_label.config(text="Private and public keys deleted successfully!", foreground="green")

    def import_public_key(self):
        # Placeholder for logic
        self.status_label.config(text="Public key imported successfully!", foreground="green")

    def import_both_keys(self):
        # Placeholder for logic
        self.status_label.config(text="Private and public keys imported successfully!", foreground="green")

    def export_public_key(self):
        # Placeholder for logic
        self.status_label.config(text="Public key exported successfully!", foreground="green")

    def export_both_keys(self):
        # Placeholder for logic
        self.status_label.config(text="Private and public keys exported successfully!", foreground="green")

    def generate_keys(self):
        # Placeholder for logic
        self.status_label.config(text="Keys generated successfully!", foreground="green")

    def show_keys_page(self):
        frame = self.pages["Keys"]
        frame.tkraise()

    def show_private_ring_page(self):
        frame = self.pages["Private Ring"]
        frame.tkraise()

    def show_public_ring_page(self):
        frame = self.pages["Public Ring"]
        frame.tkraise()

    def show_send_message_page(self):
        frame = self.pages["Send Message"]
        frame.tkraise()

    def show_receive_message_page(self):
        frame = self.pages["Receive Message"]
        frame.tkraise()
