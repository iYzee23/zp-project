import platform
import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Global.Variables import private_rings, public_rings, users
from Algorithms.RSA import RSA
from Algorithms.FileUtil import FileUtil
from Structures.Options import Options
from Structures.Message import Message

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
            # self.username_entry.delete(0, tk.END)
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
        for user in users:
            if(user[1]+"###"+user[2]) == username:
                return True
        return False

    def get_user(self):
        username = self.username_entry.get()
        for user in users:
            if(user[1]+"###"+user[2]) == username:
                return user
        return None

    def create_main_application(self):
        self.import_data()
        self.create_menu()
        self.create_keys_page()
        self.create_private_ring_page()
        self.create_public_ring_page()
        self.create_send_message_page()
        self.create_receive_message_page()

    def import_data(self):
        self.user = self.get_user()
        self.public_ring = public_rings[self.user[1] + "###" + self.user[2]]
        self.private_ring = private_rings[self.user[1] + "###" + self.user[2]]

    def create_menu(self):
        menu_bar = tk.Menu(self)
        os_name = platform.system()

        if os_name == "Windows":
            menu_bar = tk.Menu(self)
            menu_bar.add_command(label="Keys", command=self.show_keys_page)
            menu_bar.add_command(label="Private Ring", command=self.show_private_ring_page)
            menu_bar.add_command(label="Public Ring", command=self.show_public_ring_page)
            menu_bar.add_command(label="Send Message", command=self.show_send_message_page)
            menu_bar.add_command(label="Receive Message", command=self.show_receive_message_page)
            menu_bar.add_command(label="Logout", command=self.logout)

        else:
            keys_menu = tk.Menu(menu_bar, tearoff=0)
            keys_menu.add_command(label="Keys", command=self.show_keys_page)
            menu_bar.add_cascade(label="Keys", menu=keys_menu)

            private_ring_menu = tk.Menu(menu_bar, tearoff=0)
            private_ring_menu.add_command(label="Private Ring", command=self.show_private_ring_page)
            menu_bar.add_cascade(label="Private Ring", menu=private_ring_menu)

            public_ring_menu = tk.Menu(menu_bar, tearoff=0)
            public_ring_menu.add_command(label="Public Ring", command=self.show_public_ring_page)
            menu_bar.add_cascade(label="Public Ring", menu=public_ring_menu)

            send_message_menu = tk.Menu(menu_bar, tearoff=0)
            send_message_menu.add_command(label="Send Message", command=self.show_send_message_page)
            menu_bar.add_cascade(label="Send Message", menu=send_message_menu)

            receive_message_menu = tk.Menu(menu_bar, tearoff=0)
            receive_message_menu.add_command(label="Receive Message", command=self.show_receive_message_page)
            menu_bar.add_cascade(label="Receive Message", menu=receive_message_menu)

            logout_menu = tk.Menu(menu_bar, tearoff=0)
            logout_menu.add_command(label="Logout", command=self.logout)
            menu_bar.add_cascade(label="Logout", menu=logout_menu)

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
        self.email_var=tk.StringVar(value=self.user[2])
        self.email_entry = ttk.Entry(parent, textvariable=self.email_var, state='readonly')
        self.email_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(parent, text="Name:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.name_var = tk.StringVar(value=self.user[1])
        self.name_entry = ttk.Entry(parent, textvariable=self.name_var, state='readonly')
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
        public_values = [str(row.key_id) for row in self.public_ring.ring.values()]
        private_values = [str(row.key_id) for row in self.private_ring.ring.values()]

        self.export_public_selection = ttk.Combobox(parent, values=public_values)
        self.export_public_selection.grid(row=9, column=0, columnspan=2, padx=10, pady=5)

        self.export_both_selection = ttk.Combobox(parent, values=private_values)
        self.export_both_selection.grid(row=9, column=2, columnspan=2, padx=10, pady=5)

        export_public_button = ttk.Button(parent, text="Export Public key", command=self.export_public_key)
        export_public_button.grid(row=10, column=0, columnspan=2, pady=10)

        export_both_button = ttk.Button(parent, text="Export Private & Public keys", command=self.export_both_keys)
        export_both_button.grid(row=10, column=2, columnspan=2, pady=10)

    def create_delete_keys_section(self, parent):
        public_values = [str(row.key_id) for row in self.public_ring.ring.values()]
        private_values = [str(row.key_id) for row in self.private_ring.ring.values()]

        self.delete_public_selection = ttk.Combobox(parent, values=public_values)
        self.delete_public_selection.grid(row=13, column=0, columnspan=2, padx=10, pady=5)

        self.delete_both_selection = ttk.Combobox(parent, values=private_values)
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
        i=0
        for row in self.private_ring.ring.values():
            text_widget.insert("end", f"Private Ring Entry {i}\n")
            text_widget.insert("end", f"{str(row)}")
            text_widget.insert("end", "-" * 80 + "\n")
            i+=1

        button_frame = ttk.Frame(private_ring_frame)
        button_frame.pack(pady=10)

        view_button = ttk.Button(button_frame, text="View more details", command=self.create_private_key_modal_page)
        view_button.pack()

    def create_private_key_modal_page(self):
        private_values = [str(row.key_id) for row in self.private_ring.ring.values()]


        self.private_key_modal = tk.Toplevel(self)
        self.private_key_modal.title("Private Key Modal")
        self.private_key_modal.geometry("300x200")
        self.private_key_modal.grab_set()  # Makes the modal window modal

        ttk.Label(self.private_key_modal, text="Select key-id option:").grid(row=0, column=0, padx=10, pady=10)
        self.modal_private_selection = ttk.Combobox(self.private_key_modal, values=private_values)
        self.modal_private_selection.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.private_key_modal, text="Enter password:").grid(row=1, column=0, padx=10, pady=10)
        self.modal_password_entry = ttk.Entry(self.private_key_modal, show="*")
        self.modal_password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.modal_submit_button = ttk.Button(
            self.private_key_modal,
            text="See private key",
            command=self.show_private_key
        )
        self.modal_submit_button.grid(row=2, column=0, columnspan=2, pady=20)

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
        i=0
        for row in self.public_ring.ring.values():
            text_widget.insert("end", f"Public Ring Entry {i}\n")
            text_widget.insert("end", f"{str(row)}")
            text_widget.insert("end", "-" * 80 + "\n")
            i+=1
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
        self.enc_user_combo.bind("<<ComboboxSelected>>", self.toggle_user_key_id)
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
        self.send_message_text = tk.Text(send_message_frame, width=80, height=15)
        self.send_message_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        send_button = ttk.Button(send_message_frame, text="Send Message", command=self.send_message)
        send_button.grid(row=3, column=0, columnspan=2, pady=10)

    def toggle_authentication(self):
        if self.auth_var.get():
            self.auth_keyid_combo.config(
                state="normal",
                values=[str(row.key_id) for row in self.private_ring.ring.values()]
            )
        else:
            self.auth_keyid_combo.config(state="disabled")

    def toggle_encryption(self):
        if self.enc_var.get():
            self.enc_user_combo.config(state="normal", values=[row.user_id for row in self.public_ring.ring.values()])
            self.enc_keyid_combo.config(state="normal")
            self.algorithm_combo.config(state="normal", values=["AES128", "DES3"])
        else:
            self.enc_user_combo.config(state="disabled")
            self.enc_keyid_combo.config(state="disabled")
            self.algorithm_combo.config(state="disabled")

    def toggle_user_key_id(self, event):
        if self.enc_user_combo.get() != "":
            key_id_values = [row.key_id for row in self.public_ring.ring.values() if row.user_id == self.enc_user_combo.get()]
            self.enc_keyid_combo["values"] = key_id_values

    def send_message(self):
        error_string = ""

        if self.auth_var.get() == True:
            if self.auth_keyid_combo.get() == '':
                error_string += "No private key selected!\n"

        if self.enc_var.get() == True:
            if self.enc_user_combo.get() == '':
                error_string += "No user selected!\n"

            if self.enc_user_combo.get() != '' and self.enc_keyid_combo.get() == '':
                error_string += "No user's public key selected!\n"

            if self.algorithm_combo.get() == '':
                error_string += "No algorithm selected!\n"

            for row in self.public_ring.ring.values():
                if row.user_id == self.enc_user_combo.get() and row.key_id != int(self.enc_keyid_combo.get()):
                    error_string += "The selected public key does not belong to the selected user!\n"
        if error_string != "":
            messagebox.showerror("Error", error_string)
            return
        options = Options(self.enc_var.get(), self.auth_var.get(), self.comp_var.get(), self.radix_var.get(), self.algorithm_combo.get())
        message = Message(self.send_message_text.get("1.0", 'end-1c'), None, datetime.datetime.now(), options)

        sender_ring_row = None
        recipient_ring_row = None
        if self.auth_var.get() == True:
            for row in self.private_ring.ring.values():
                if row.key_id == int(self.auth_keyid_combo.get()):
                    sender_ring_row = row
        if self.enc_var.get() == True:
            for row in self.public_ring.ring.values():
                if row.key_id == int(self.enc_keyid_combo.get()):
                    recipient_ring_row = row

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            message.filename = filename
            message_string = Message.send_message(message, sender_ring_row, self.user[0], recipient_ring_row)
            FileUtil.export_message(filename, message_string)

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

        self.sender_name_label = ttk.Label(labels_frame, text="", font=("Helvetica", 10),foreground="black")
        self.sender_name_label.grid(row=1, column=0, sticky="w", pady=5)

        self.sender_mail_label = ttk.Label(labels_frame, text="", font=("Helvetica", 10),foreground="black")
        self.sender_mail_label.grid(row=2, column=0, sticky="w", pady=5)

        self.enc_label = ttk.Label(labels_frame, text="Encryption AES128/DES3 [option]", font=("Helvetica", 10), foreground="black")
        self.enc_label.grid(row=3, column=0, sticky="w", pady=5)

        self.comp_label = ttk.Label(labels_frame, text="Compression [option]", font=("Helvetica", 10), foreground="black")
        self.comp_label.grid(row=4, column=0, sticky="w", pady=5)

        self.radix_label = ttk.Label(labels_frame, text="Radix64 [option]", font=("Helvetica", 10), foreground="black")
        self.radix_label.grid(row=5, column=0, sticky="w", pady=5)

        self.enc_algo_label = ttk.Label(labels_frame, text="", font=("Helvetica", 10))
        self.enc_algo_label.grid(row=6, column=0, sticky="w", pady=5)

        self.result_label = ttk.Label(labels_frame, text="", font=("Helvetica", 10))
        self.result_label.grid(row=7, column=0, sticky="w", pady=5)

        ttk.Label(receive_message_frame, text="Message:").grid(row=1, column=0, columnspan=2, sticky="w", padx=10)
        self.received_message_text = tk.Text(receive_message_frame, width=80, height=15)
        self.received_message_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        buttons_frame = ttk.Frame(receive_message_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=10)

        receive_button = ttk.Button(buttons_frame, text="Receive Message", command=self.receive_message)
        receive_button.grid(row=0, column=0, padx=5)

        save_button = ttk.Button(buttons_frame, text="Save Message", command=self.save_message)
        save_button.grid(row=0, column=1, padx=5)

    def receive_message(self):
        try:
            message_string = FileUtil.import_message()

            if message_string is not None:
                message, sender = Message.receive_message(message_string, self.private_ring, self.user[0], self.public_ring)
                self.received_message_text.configure(state="normal")
                self.received_message_text.delete("1.0", tk.END)
                self.received_message_text.insert(tk.END, message)
                self.received_message_text.configure(state="disabled")

                options = message.options

                if options.authentication == "True":
                    self.auth_label.configure(text="Authentication/Signature present")
                    self.auth_label.configure(foreground="green")
                    sender_data = sender.split("###")
                    self.sender_name_label.configure(text=sender_data[0].strip())
                    self.sender_name_label.configure(foreground="green")
                    self.sender_mail_label.configure(text=sender_data[1].strip())
                    self.sender_mail_label.configure(foreground="green")
                elif options.authentication == "False":
                    self.auth_label.configure(text="Authentication/Signature not present")
                    self.auth_label.configure(foreground="red")

                if options.encryption == "True":
                    self.enc_label.configure(text="Encryption present")
                    self.enc_label.configure(foreground="green")
                    self.enc_algo_label.configure(text=options.algorithm)
                    self.enc_algo_label.configure(foreground="green")
                elif options.encryption == "False":
                    self.enc_label.configure(text="Encryption not present")
                    self.enc_label.configure(foreground="red")
                    self.enc_algo_label.configure(text="")

                if options.compression == "True":
                    self.comp_label.configure(text="Compression present")
                    self.comp_label.configure(foreground="green")
                elif options.compression == "False":
                    self.comp_label.configure(text="Compression not present")
                    self.comp_label.configure(foreground="red")

                if options.radix64 == "True":
                    self.radix_label.configure(text="Radix present")
                    self.radix_label.configure(foreground="green")
                elif options.radix64 == "False":
                    self.radix_label.configure(text="Radix not present")
                    self.radix_label.configure(foreground="red")

                self.result_label.configure(text="Message successfully received!", foreground="green")

        except ValueError as e:
            self.received_message_text.configure(state="normal")
            self.received_message_text.delete("1.0", tk.END)
            self.received_message_text.insert(tk.END, "")
            self.received_message_text.configure(state="disabled")
            self.result_label.configure(text=f"{e}", foreground="red")

    def save_message(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            FileUtil.export_message(filename, self.received_message_text.get("1.0", tk.END))
            with open(filename, 'w') as file:
                file.write(self.received_message_text.get("1.0", tk.END))
            messagebox.showinfo("Success", "Message saved successfully!")

    def logout(self):
        self.username_entry.delete(0, tk.END)
        self.show_page("Login")

    def delete_public_key(self):
        value = self.delete_public_selection.get()
        if value != "":
            for row in self.public_ring.ring.values():
                if row.key_id == int(value):
                    del self.public_ring.ring[row.key_id]
                    self.create_main_application()
                    self.show_page("Keys")

                    self.status_label.config(text="Public key deleted successfully!", foreground="green")
                    return
        self.status_label.config(text="You must choose key id!", foreground="red")

    def delete_both_keys(self):
        value = self.delete_both_selection.get()
        if value != "":
            for row in self.private_ring.ring.values():
                if row.key_id == int(value):
                    del self.private_ring.ring[row.key_id]
                    self.create_main_application()
                    self.show_page("Keys")

                    self.status_label.config(text="Private and public keys deleted successfully!", foreground="green")
                    return

        self.status_label.config(text="You must choose key id!", foreground="red")

    def import_public_key(self):
        try:
            row = RSA.import_public_ring_row_tk()

            if row is not None:
                self.public_ring.ring[row.key_id] = row

                self.create_main_application()
                self.show_page("Keys")

                self.status_label.config(text="Public key imported successfully!", foreground="green")

        except ValueError as e:
            print(f"Caught exception: {e}")

    def import_both_keys(self):
        try:
            row = RSA.import_private_ring_row_tk(self.user[0])

            if row is not None:
                if row.user_id != (self.user[1] + "###" + self.user[2]):
                    self.status_label.config(text="Private key does not belong to this user!", foreground="red")
                else:
                    self.private_ring.ring[row.key_id] = row

                    self.create_main_application()
                    self.show_page("Keys")

                    self.status_label.config(text="Private and public keys imported successfully!", foreground="green")

        except ValueError as e:
            print(f"Caught exception: {e}")

    def export_public_key(self):
        value = self.export_public_selection.get()
        if value != "":
            for row in self.public_ring.ring.values():
                if row.key_id == int(value):
                    RSA.export_public_ring_row_tk(row)
                    self.create_main_application()
                    self.show_page("Keys")

                    self.status_label.config(text="Public key exported successfully!", foreground="green")
                    return

        self.status_label.config(text="You must choose key id!", foreground="red")

    def export_both_keys(self):
        value = self.export_both_selection.get()
        if value != "":
            for row in self.private_ring.ring.values():
                if row.key_id == int(value):
                    RSA.export_private_ring_row_tk(row, self.user[0])

                    self.create_main_application()
                    self.show_page("Keys")

                    self.status_label.config(text="Both keys exported successfully!", foreground="green")
                    return

        self.status_label.config(text="You must choose key id!", foreground="red")

    def generate_keys(self):
        if self.user[0]!=self.password_entry.get():
            self.status_label.config(text="Wrong password!", foreground="red")
            self.password_entry.delete(0, tk.END)
        elif self.key_size.get() == "":
            self.password_entry.delete(0, tk.END)
            self.status_label.config(text="Key size not chosen!", foreground="red")
        else:
            (public_key, private_key) =RSA.generate_keys(int(self.key_size.get()))
            self.public_ring.add_row(public_key, self.user[1], self.user[2])
            self.private_ring.add_row(public_key, private_key, self.user[0], self.user[1], self.user[2], self.user[3])
            self.create_main_application()
            self.show_page("Keys")
            self.status_label.config(text="Keys generated successfully!", foreground="green")

    def show_keys_page(self):
        frame = self.pages["Keys"]
        frame.tkraise()

    def show_private_ring_page(self):
        frame = self.pages["Private Ring"]
        frame.tkraise()

    def show_private_key(self):
        key_id = self.modal_private_selection.get()
        password = self.modal_password_entry.get()
        self.private_key_modal.destroy()
        if key_id != "":
            for row in self.private_ring.ring.values():
                if row.key_id == int(key_id):
                    private_key =row.get_private_key(password)
                    if(private_key is not None):
                        messagebox.showinfo("Private Key", private_key)
                        return
                    messagebox.showerror("Private Key", "Password is incorrect. Please try again.!")
        else:
            messagebox.showerror("Private Key", "Key-id field is empty!")

    def show_public_ring_page(self):
        frame = self.pages["Public Ring"]
        frame.tkraise()

    def show_send_message_page(self):
        frame = self.pages["Send Message"]
        frame.tkraise()

    def show_receive_message_page(self):
        frame = self.pages["Receive Message"]
        frame.tkraise()
