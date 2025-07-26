import os
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image, ImageTk
import io
import wave
import struct
from Crypto.Cipher import AES, DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import threading
import json
import base64

# Set appearance mode and default color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
class GlassCryptoApp(ctk.CTk):
    # Define constants for key lengths, salt size, IV size
    SALT_SIZE = 16
    AES_KEY_SIZE = 32  # Use AES-256
    AES_IV_SIZE = AES.block_size  # 16 bytes
    DES_KEY_SIZE = 8  # DES key size
    DES_IV_SIZE = DES.block_size  # 8 bytes
    PBKDF2_ITERATIONS = 100000  # Number of iterations for PBKDF2
    
    # Audio file formats supported
    AUDIO_EXTENSIONS = ['.wav', '.mp3', '.ogg', '.flac', '.aac', '.m4a']
    
    # Header magic bytes to identify our encrypted files
    MAGIC_HEADER = b'SECENC'
    VERSION = b'\x01'
    
    # File type flags
    FILE_TYPE_REGULAR = b'\x00'
    FILE_TYPE_AUDIO = b'\x01'

    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("Secure File Encryptor")
        self.geometry("800x600")
        self.minsize(800, 600)
        
        # Set up grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create main frame with glass effect
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color=("#0a0e17", "#0a0e17"))
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        # Configure main frame grid
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(5, weight=1)
        
        # App title
        self.title_label = ctk.CTkLabel(
            self.main_frame, 
            text="Secure File Encryptor", 
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#00a3ff"
        )
        self.title_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Subtitle
        self.subtitle_label = ctk.CTkLabel(
            self.main_frame, 
            text="Encrypt and decrypt files with AES or DES", 
            font=ctk.CTkFont(size=14),
            text_color="#a0b4d0"
        )
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20))
        
        # Create glass-effect frame for file selection
        self.file_frame = ctk.CTkFrame(
            self.main_frame, 
            corner_radius=10, 
            fg_color=("#141e30", "#141e30"),
            border_width=1,
            border_color="#1f2b42"
        )
        self.file_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        self.file_frame.grid_columnconfigure(1, weight=1)
        
        # File selection
        self.file_label = ctk.CTkLabel(
            self.file_frame, 
            text="Selected File:",
            font=ctk.CTkFont(size=12),
            text_color="#a0b4d0"
        )
        self.file_label.grid(row=0, column=0, padx=(15, 5), pady=15)
        
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ctk.CTkEntry(
            self.file_frame, 
            textvariable=self.file_path_var,
            state="readonly",
            width=400,
            fg_color=("#0a0e17", "#0a0e17"),
            border_color="#1f2b42",
            text_color="#ffffff"
        )
        self.file_path_entry.grid(row=0, column=1, padx=(5, 5), pady=15, sticky="ew")
        
        self.browse_button = ctk.CTkButton(
            self.file_frame, 
            text="Browse",
            command=self.browse_file,  # Ensure this points to the correct method
            fg_color="#0062ff",
            hover_color="#0051d3",
            text_color="#ffffff",
            corner_radius=8
        )
        self.browse_button.grid(row=0, column=2, padx=(5, 15), pady=15)
        
        # Create options frame
        self.options_frame = ctk.CTkFrame(
            self.main_frame, 
            corner_radius=10, 
            fg_color=("#141e30", "#141e30"),
            border_width=1,
            border_color="#1f2b42"
        )
        self.options_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        self.options_frame.grid_columnconfigure(0, weight=1)
        self.options_frame.grid_columnconfigure(1, weight=1)
        
        # Algorithm selection
        self.algo_label = ctk.CTkLabel(
            self.options_frame, 
            text="Algorithm:",
            font=ctk.CTkFont(size=12),
            text_color="#a0b4d0"
        )
        self.algo_label.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
        
        self.algo_var = tk.StringVar(value="AES")
        self.algo_frame = ctk.CTkFrame(
            self.options_frame, 
            fg_color="transparent"
        )
        self.algo_frame.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="w")
        
        self.aes_radio = ctk.CTkRadioButton(
            self.algo_frame, 
            text="AES (Recommended)",
            variable=self.algo_var,
            value="AES",
            fg_color="#0062ff",
            border_color="#a0b4d0",
            hover_color="#0051d3",
            text_color="#ffffff"
        )
        self.aes_radio.grid(row=0, column=0, padx=(0, 15), pady=0)
        
        self.des_radio = ctk.CTkRadioButton(
            self.algo_frame, 
            text="DES (Legacy)",
            variable=self.algo_var,
            value="DES",
            fg_color="#0062ff",
            border_color="#a0b4d0",
            hover_color="#0051d3",
            text_color="#ffffff"
        )
        self.des_radio.grid(row=0, column=1, padx=0, pady=0)
        
        # Operation selection
        self.op_label = ctk.CTkLabel(
            self.options_frame, 
            text="Operation:",
            font=ctk.CTkFont(size=12),
            text_color="#a0b4d0"
        )
        self.op_label.grid(row=0, column=1, padx=15, pady=(15, 5), sticky="w")
        
        self.op_var = tk.StringVar(value="Encrypt")
        self.op_frame = ctk.CTkFrame(
            self.options_frame, 
            fg_color="transparent"
        )
        self.op_frame.grid(row=1, column=1, padx=15, pady=(0, 15), sticky="w")
        
        self.encrypt_radio = ctk.CTkRadioButton(
            self.op_frame, 
            text="Encrypt",
            variable=self.op_var,
            value="Encrypt",
            fg_color="#0062ff",
            border_color="#a0b4d0",
            hover_color="#0051d3",
            text_color="#ffffff"
        )
        self.encrypt_radio.grid(row=0, column=0, padx=(0, 15), pady=0)
        
        self.decrypt_radio = ctk.CTkRadioButton(
            self.op_frame, 
            text="Decrypt",
            variable=self.op_var,
            value="Decrypt",
            fg_color="#0062ff",
            border_color="#a0b4d0",
            hover_color="#0051d3",
            text_color="#ffffff"
        )
        self.decrypt_radio.grid(row=0, column=1, padx=0, pady=0)
        
        # Password input
        self.password_frame = ctk.CTkFrame(
            self.main_frame, 
            corner_radius=10, 
            fg_color=("#141e30", "#141e30"),
            border_width=1,
            border_color="#1f2b42"
        )
        self.password_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        self.password_frame.grid_columnconfigure(1, weight=1)
        
        self.password_label = ctk.CTkLabel(
            self.password_frame, 
            text="Password:",
            font=ctk.CTkFont(size=12),
            text_color="#a0b4d0"
        )
        self.password_label.grid(row=0, column=0, padx=(15, 5), pady=15)
        
        self.password_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(
            self.password_frame, 
            textvariable=self.password_var,
            show="•",
            width=400,
            fg_color=("#0a0e17", "#0a0e17"),
            border_color="#1f2b42",
            text_color="#ffffff"
        )
        self.password_entry.grid(row=0, column=1, padx=(5, 15), pady=15, sticky="ew")
        
        # Status and action frame
        self.status_frame = ctk.CTkFrame(
            self.main_frame, 
            corner_radius=10, 
            fg_color=("#141e30", "#141e30"),
            border_width=1,
            border_color="#1f2b42"
        )
        self.status_frame.grid(row=5, column=0, padx=20, pady=10, sticky="nsew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        self.status_frame.grid_rowconfigure(0, weight=1)
        
        # Status message
        self.status_var = tk.StringVar()
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            textvariable=self.status_var,
            font=ctk.CTkFont(size=12),
            text_color="#00a3ff",
            wraplength=700
        )
        self.status_label.grid(row=0, column=0, padx=20, pady=(20, 0), sticky="ew")
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.status_frame,
            orientation="horizontal",
            mode="determinate",
            progress_color="#00a3ff",
            corner_radius=5
        )
        self.progress_bar.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="ew")
        self.progress_bar.set(0)
        
        # Action buttons frame
        self.button_frame = ctk.CTkFrame(
            self.main_frame, 
            fg_color="transparent"
        )
        self.button_frame.grid(row=6, column=0, padx=20, pady=(10, 20), sticky="ew")
        self.button_frame.grid_columnconfigure(0, weight=1)
        self.button_frame.grid_columnconfigure(1, weight=1)
        self.button_frame.grid_columnconfigure(2, weight=1)
        
        # Process button
        self.process_button = ctk.CTkButton(
            self.button_frame, 
            text="Process File",
            command=self.start_processing,
            fg_color="#0062ff",
            hover_color="#0051d3",
            text_color="#ffffff",
            corner_radius=8,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.process_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        # Save button
        self.save_button = ctk.CTkButton(
            self.button_frame, 
            text="Save File",
            command=self.save_file,
            fg_color="#141e30",
            hover_color="#1f2b42",
            text_color="#ffffff",
            corner_radius=8,
            height=40,
            font=ctk.CTkFont(size=14),
            state="disabled"
        )
        self.save_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        # Exit button
        self.exit_button = ctk.CTkButton(
            self.button_frame, 
            text="Exit",
            command=self.quit,
            fg_color="#141e30",
            hover_color="#1f2b42",
            text_color="#ffffff",
            corner_radius=8,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.exit_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")
        
        # File type indicator with icon
        self.file_info_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color="transparent"
        )
        self.file_info_frame.grid(row=7, column=0, padx=20, pady=(0, 10))
        
        # Audio icon indicator (blue wave icon for audio files)
        self.audio_icon_label = ctk.CTkLabel(
            self.file_info_frame,
            text="🎵",  # Audio icon
            font=ctk.CTkFont(size=16),
            text_color="#00a3ff"
        )
        self.audio_icon_label.grid(row=0, column=0, padx=(0, 5))
        self.audio_icon_label.grid_remove()  # Hide initially
        
        # File type text
        self.file_type_var = tk.StringVar(value="No file selected")
        self.file_type_label = ctk.CTkLabel(
            self.file_info_frame, 
            textvariable=self.file_type_var,
            font=ctk.CTkFont(size=12),
            text_color="#a0b4d0"
        )
        self.file_type_label.grid(row=0, column=1, padx=0)
        
        # Initialize variables
        self.processed_data = None
        self.is_audio_file = False
        self.original_file_extension = ""
        self.audio_metadata = {}
        self.file_type = self.FILE_TYPE_REGULAR

    def browse_file(self):
        """Open file dialog to select a file for processing"""
        file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[
                ("All Files", "*.*"),  # Allow all files
                ("Audio Files", "*.wav;*.mp3;*.ogg;*.flac;*.aac;*.m4a"),
                ("Text Files", "*.txt"),
                ("Image Files", "*.jpg;*.jpeg;*.png"),
                ("Document Files", "*.pdf;*.docx"),
                ("Encrypted Files", "*.enc;*.aes;*.des")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.status_var.set("File selected. Ready for processing.")
            self.save_button.configure(state="disabled")
            self.processed_data = None
        else:
            self.status_var.set("No file selected.")

            # Check if it's an audio file
            ext = os.path.splitext(file_path)[1].lower()
            self.original_file_extension = ext
            
            # Check if it's an encrypted file
            if ext in ['.enc', '.aes', '.des']:
                self.file_type_var.set(f"Encrypted file: {os.path.basename(file_path)}")
                self.audio_icon_label.grid_remove()  # Hide audio icon until we know it's audio
                
                # Try to detect if it's an encrypted audio file by reading header
                try:
                    with open(file_path, 'rb') as f:
                        header = f.read(len(self.MAGIC_HEADER) + 1 + 1)  # Magic + Version + FileType
                        if (len(header) >= len(self.MAGIC_HEADER) + 2 and 
                            header[:len(self.MAGIC_HEADER)] == self.MAGIC_HEADER and
                            header[len(self.MAGIC_HEADER)] == ord(self.VERSION) and
                            header[len(self.MAGIC_HEADER) + 1] == ord(self.FILE_TYPE_AUDIO)):
                            self.is_audio_file = True
                            self.file_type = self.FILE_TYPE_AUDIO
                            self.audio_icon_label.grid()  # Show audio icon
                            self.file_type_var.set(f"Encrypted audio file: {os.path.basename(file_path)}")
                        else:
                            self.is_audio_file = False
                            self.file_type = self.FILE_TYPE_REGULAR
                except:
                    # If we can't read the header, assume it's a regular encrypted file
                    self.is_audio_file = False
                    self.file_type = self.FILE_TYPE_REGULAR
            
            elif ext in self.AUDIO_EXTENSIONS:
                self.is_audio_file = True
                self.file_type = self.FILE_TYPE_AUDIO
                self.file_type_var.set(f"Audio file detected: {ext[1:].upper()}")
                self.audio_icon_label.grid()  # Show audio icon
                
                # Try to get audio metadata for WAV files
                if ext == '.wav':
                    try:
                        with wave.open(file_path, 'rb') as wav_file:
                            self.audio_metadata = {
                                'channels': wav_file.getnchannels(),
                                'sample_width': wav_file.getsampwidth(),
                                'framerate': wav_file.getframerate(),
                                'frames': wav_file.getnframes(),
                                'compression': wav_file.getcomptype()
                            }
                            self.status_var.set(f"Audio file loaded: {ext[1:].upper()} format, "
                                              f"{self.audio_metadata['channels']} channel(s), "
                                              f"{self.audio_metadata['framerate']} Hz")
                    except Exception as e:
                        print(f"Error reading WAV metadata: {e}")
                        self.audio_metadata = {}
            else:
                self.is_audio_file = False
                self.file_type = self.FILE_TYPE_REGULAR
                self.file_type_var.set(f"File type: {ext[1:].upper() if ext else 'Unknown'}")
                self.audio_icon_label.grid_remove()  # Hide audio icon
            
            # Reset progress bar
            self.progress_bar.set(0)

    def _derive_key(self, password, salt, key_size):
        """Derives a key from the password using PBKDF2."""
        return PBKDF2(password.encode("utf-8"), salt, dkLen=key_size, count=self.PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

    def _encrypt(self, data, password, algo):
        """Encrypts data using the specified algorithm (AES or DES)."""
        salt = get_random_bytes(self.SALT_SIZE)
        
        # Create header with magic bytes, version, and file type
        header = self.MAGIC_HEADER + self.VERSION + (self.FILE_TYPE_AUDIO if self.is_audio_file else self.FILE_TYPE_REGULAR)
        
        # Store audio metadata if it's an audio file
        metadata_bytes = b''
        if self.is_audio_file and self.audio_metadata:
            # Convert metadata to JSON string, then to bytes
            metadata_json = json.dumps(self.audio_metadata).encode('utf-8')
            # Store the length of metadata as 4 bytes
            metadata_length = len(metadata_json).to_bytes(4, byteorder='big')
            metadata_bytes = metadata_length + metadata_json
        
        # Store original file extension
        ext_bytes = self.original_file_extension.encode('utf-8')
        ext_length = len(ext_bytes).to_bytes(2, byteorder='big')  # 2 bytes for extension length
        
        # Combine all header information
        full_header = header + ext_length + ext_bytes + metadata_bytes
        
        if algo == "AES":
            key = self._derive_key(password, salt, self.AES_KEY_SIZE)
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv  # Get the generated IV
            padded_data = pad(data, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return full_header + salt + iv + ciphertext
        elif algo == "DES":
            key = self._derive_key(password, salt, self.DES_KEY_SIZE)
            cipher = DES.new(key, DES.MODE_CBC)
            iv = cipher.iv  # Get the generated IV
            padded_data = pad(data, DES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return full_header + salt + iv + ciphertext
        else:
            raise ValueError("Unsupported algorithm")

    def _decrypt(self, encrypted_data, password, algo):
        """Decrypts data using the specified algorithm (AES or DES)."""
        try:
            # Check for our magic header
            if not encrypted_data.startswith(self.MAGIC_HEADER):
                # Legacy file without header, use old decryption method
                return self._legacy_decrypt(encrypted_data, password, algo)
            
            # Parse header
            header_offset = len(self.MAGIC_HEADER) + 1  # Magic + Version
            file_type = encrypted_data[header_offset:header_offset+1]
            header_offset += 1
            
            # Get original file extension
            ext_length = int.from_bytes(encrypted_data[header_offset:header_offset+2], byteorder='big')
            header_offset += 2
            ext_bytes = encrypted_data[header_offset:header_offset+ext_length]
            self.original_file_extension = ext_bytes.decode('utf-8')
            header_offset += ext_length
            
            # Get metadata if it's an audio file
            if file_type == self.FILE_TYPE_AUDIO:
                self.is_audio_file = True
                self.file_type = self.FILE_TYPE_AUDIO
                
                # Read metadata length
                metadata_length = int.from_bytes(encrypted_data[header_offset:header_offset+4], byteorder='big')
                header_offset += 4
                
                # Read and parse metadata
                if metadata_length > 0:
                    metadata_json = encrypted_data[header_offset:header_offset+metadata_length]
                    self.audio_metadata = json.loads(metadata_json.decode('utf-8'))
                    header_offset += metadata_length
            else:
                self.is_audio_file = False
                self.file_type = self.FILE_TYPE_REGULAR
            
            # Extract salt and encrypted data
            salt = encrypted_data[header_offset:header_offset+self.SALT_SIZE]
            header_offset += self.SALT_SIZE
            
            if algo == "AES":
                iv = encrypted_data[header_offset:header_offset+self.AES_IV_SIZE]
                header_offset += self.AES_IV_SIZE
                ciphertext = encrypted_data[header_offset:]
                
                key = self._derive_key(password, salt, self.AES_KEY_SIZE)
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, AES.block_size)
                return plaintext
                
            elif algo == "DES":
                iv = encrypted_data[header_offset:header_offset+self.DES_IV_SIZE]
                header_offset += self.DES_IV_SIZE
                ciphertext = encrypted_data[header_offset:]
                
                key = self._derive_key(password, salt, self.DES_KEY_SIZE)
                cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, DES.block_size)
                return plaintext
                
            else:
                raise ValueError("Unsupported algorithm")
                
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            print(f"Decryption error: {e}")  # Log the error for debugging
            raise ValueError("Decryption failed. Check password or file integrity.") from e

    def _legacy_decrypt(self, encrypted_data, password, algo):
        """Legacy decryption for files encrypted with older versions."""
        try:
            salt = encrypted_data[:self.SALT_SIZE]
            
            if algo == "AES":
                iv = encrypted_data[self.SALT_SIZE:self.SALT_SIZE+self.AES_IV_SIZE]
                ciphertext = encrypted_data[self.SALT_SIZE+self.AES_IV_SIZE:]
                key = self._derive_key(password, salt, self.AES_KEY_SIZE)
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, AES.block_size)
            elif algo == "DES":
                iv = encrypted_data[self.SALT_SIZE:self.SALT_SIZE+self.DES_IV_SIZE]
                ciphertext = encrypted_data[self.SALT_SIZE+self.DES_IV_SIZE:]
                key = self._derive_key(password, salt, self.DES_KEY_SIZE)
                cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                padded_plaintext = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, DES.block_size)
            else:
                raise ValueError("Unsupported algorithm")
                
            # Try to detect if this is audio data by checking for metadata format
            try:
                # Check if the first 4 bytes could be a metadata length
                metadata_length = int.from_bytes(plaintext[:4], byteorder='big')
                if 0 < metadata_length < 1000:  # Reasonable size for metadata
                    metadata_bytes = plaintext[4:4+metadata_length]
                    metadata_str = metadata_bytes.decode('utf-8')
                    
                    # Safely evaluate the string representation of the dictionary
                    import ast
                    self.audio_metadata = ast.literal_eval(metadata_str)
                    self.is_audio_file = True
                    self.file_type = self.FILE_TYPE_AUDIO
                    
                    # Return the actual audio data without the metadata
                    return plaintext[4+metadata_length:]
            except:
                # If there's an error parsing metadata, it's probably not audio
                pass
                
            return plaintext
                
        except (ValueError, KeyError) as e:
            print(f"Legacy decryption error: {e}")
            raise ValueError("Decryption failed. Check password or file integrity.") from e

    def start_processing(self):
        """Start processing in a separate thread to keep UI responsive"""
        # Disable buttons during processing
        self.process_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        
        # Start processing thread
        threading.Thread(target=self.process_file, daemon=True).start()

    def process_file(self):
        """Process the selected file with the chosen algorithm and operation"""
        file_path = self.file_path_var.get()
        algo = self.algo_var.get()
        op = self.op_var.get()
        password = self.password_var.get()

        if not file_path:
            self.show_error("Input Error", "Please select a file first.")
            self.enable_process_button()
            return
        if not password:
            self.show_error("Input Error", "Please enter a password.")
            self.enable_process_button()
            return

        self.update_status(f"Processing '{os.path.basename(file_path)}' using {algo} to {op}...")
        self.update_progress(0.2)  # Show some progress

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            self.update_progress(0.4)  # Update progress
            
            if op == "Encrypt":
                self.processed_data = self._encrypt(file_data, password, algo)
                self.update_status(f"File encrypted successfully with {algo}. Ready to save.")
            elif op == "Decrypt":
                self.processed_data = self._decrypt(file_data, password, algo)
                self.update_status(f"File decrypted successfully with {algo}. Ready to save.")
                
                # If it's an audio file, show the metadata
                if self.is_audio_file and self.audio_metadata:
                    metadata_str = ", ".join([f"{k}: {v}" for k, v in self.audio_metadata.items() 
                                            if k in ['channels', 'framerate']])
                    self.update_status(f"Audio file decrypted successfully. {metadata_str}. Ready to save.")
            else:
                raise ValueError("Invalid operation selected")
            
            self.update_progress(0.8)  # Update progress
            self.enable_save_button()
            self.update_progress(1.0)  # Complete progress

        except FileNotFoundError:
            self.show_error("Error", f"File not found: {file_path}")
            self.update_status("Error: File not found.")
            self.disable_save_button()
            self.update_progress(0)
        except ValueError as e:
            self.show_error("Error", f"Processing failed: {e}")
            self.update_status(f"Error: {e}")
            self.disable_save_button()
            self.update_progress(0)
        except Exception as e:
            self.show_error("Error", f"An unexpected error occurred: {e}")
            self.update_status("An unexpected error occurred during processing.")
            self.disable_save_button()
            self.update_progress(0)
            print(f"Unexpected error: {e}")  # Log unexpected errors
        finally:
            # Re-enable process button
            self.enable_process_button()

    def save_file(self):
        """Save the processed data to a file"""
        if self.processed_data is None:
            self.show_error("No Data", "No processed data available to save.")
            return

        # Suggest a filename based on original and operation
        original_path = self.file_path_var.get()
        base, ext = os.path.splitext(os.path.basename(original_path))
        op = self.op_var.get().lower()
        algo = self.algo_var.get().lower()

        if op == "encrypt":
            default_extension = f".{algo}.enc"
            suggested_filename = f"{base}_{algo}_encrypted{default_extension}"
        elif op == "decrypt":
            # For decryption, try to preserve the original file type
            if self.is_audio_file:
                if self.original_file_extension and self.original_file_extension in self.AUDIO_EXTENSIONS:
                    suggested_filename = f"{base}_decrypted{self.original_file_extension}"
                else:
                    suggested_filename = f"{base}_decrypted.wav"  # Default to WAV for audio
            elif self.original_file_extension:
                suggested_filename = f"{base}_decrypted{self.original_file_extension}"
            elif original_path.endswith(('.enc', '.aes', '.des')):
                base_dec = os.path.splitext(base)[0]  # Remove .enc/.aes/.des part
                ext_dec = os.path.splitext(base)[1]  # Get original extension if double-ext like .txt.enc
                suggested_filename = f"{base_dec}_decrypted{ext_dec if ext_dec else '.bin'}"
            else:
                suggested_filename = f"{base}_decrypted{ext if ext else '.bin'}"  # Default extension if unknown
        else:
            suggested_filename = "processed_file"

        save_path = filedialog.asksaveasfilename(
            initialfile=suggested_filename,
            defaultextension=".*",
            filetypes=[("All Files", ".")]
        )

        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(self.processed_data)
                self.update_status(f"File saved successfully to {os.path.basename(save_path)}")
                self.show_info("Success", "File saved successfully.")
                self.update_progress(0)  # Reset progress bar after successful save
            except Exception as e:
                self.show_error("Save Error", f"Failed to save file: {e}")
                self.update_status("Error saving file.")
        else:
            self.update_status("Save operation cancelled.")

    # Helper methods to update UI from threads
    def update_status(self, message):
        """Update status message safely from any thread"""
        self.after(0, lambda: self.status_var.set(message))
    
    def update_progress(self, value):
        """Update progress bar safely from any thread"""
        self.after(0, lambda: self.progress_bar.set(value))
    
    def enable_save_button(self):
        """Enable save button safely from any thread"""
        self.after(0, lambda: self.save_button.configure(state="normal"))
    
    def disable_save_button(self):
        """Disable save button safely from any thread"""
        self.after(0, lambda: self.save_button.configure(state="disabled"))
    
    def enable_process_button(self):
        """Enable process button safely from any thread"""
        self.after(0, lambda: self.process_button.configure(state="normal"))
    
    def show_error(self, title, message):
        """Show error message safely from any thread"""
        self.after(0, lambda: messagebox.showerror(title, message))
    
    def show_info(self, title, message):
        """Show info message safely from any thread"""
        self.after(0, lambda: messagebox.showinfo(title, message))

if __name__ == "__main__":
    app = GlassCryptoApp()
    app.mainloop()
