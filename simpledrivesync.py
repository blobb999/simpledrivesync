import os
import shutil
import threading
import ctypes
import hashlib
import xxhash
import time
from tkinter import filedialog, messagebox, Tk, Button, Label, Entry, StringVar, Text, Scrollbar, END, N, S, E, W, Frame, Checkbutton, BooleanVar
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor
from tkinter.ttk import Sizegrip

class SyncApp:
    def __init__(self):
        self.stop_sync_flag = False
        self.deleted_count = 0
        self.sync_thread = None

sync_app = SyncApp()

def start_sync_thread():
    if sync_app.sync_thread is not None and sync_app.sync_thread.is_alive():
        messagebox.showerror("Error", "A synchronization process is already running.")
        return

    # Re-enable the progress bar
    sync_app.stop_sync_flag = False
    progress_bar.grid(column=1, row=4, sticky=(E, W))
    progress_bar.start()

    sync_app.sync_thread = threading.Thread(target=start_sync)
    sync_app.sync_thread.start()

def update_status_text(text):
    status_text.config(state="normal")
    status_text.insert(END, text)
    status_text.see(END)
    status_text.config(state="disabled")
    root.update_idletasks()

def copy_file(src_file_path, dest_file_path, status_text):
    try:
        shutil.copy2(src_file_path, dest_file_path)
        update_status_text(f"Copied file: {dest_file_path}\n")
    except Exception as e:
        update_status_text(f"Error copying file {src_file_path} to {dest_file_path}: {e}\n")

def browse_src_directory():
    directory = filedialog.askdirectory()
    src_folder_path.set(directory)

def browse_dest_directory():
    directory = filedialog.askdirectory()
    dest_folder_path.set(directory)

def has_admin_permission(folder_path):
    try:
        return os.access(folder_path, os.W_OK)
    except:
        return False

def update_progress_bar(progress_bar):
    if sync_app.stop_sync_flag:
        progress_bar.stop()
        progress_bar.grid_remove()
        return
    progress_bar.step(1)
    root.after(300, lambda: update_progress_bar(progress_bar))

def truncate_path(path, max_length):
    if len(path) <= max_length:
        return path
    else:
        return '...' + path[-(max_length - 3):]
    
def hash_file(file_path):
    chunk_size = 1024 * 1024  # 1 MB
    file_hash = xxhash.xxh64()

    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            file_hash.update(chunk)

    return file_hash.hexdigest()

def should_copy(src_file_path, dest_file_path, use_hash, compare_mod_date):
    if not os.path.exists(dest_file_path):
        return True

    if not use_hash and not compare_mod_date:
        return False

    if os.path.getsize(src_file_path) != os.path.getsize(dest_file_path):
        return True

    if compare_mod_date:
        src_mod_time = os.path.getmtime(src_file_path)
        dest_mod_time = os.path.getmtime(dest_file_path)
        return src_mod_time > dest_mod_time

    if use_hash:
        src_hash = hash_file(src_file_path)
        dest_hash = hash_file(dest_file_path)

        return src_hash != dest_hash

def is_system_directory(folder_path):
    return os.path.isdir(folder_path) and ctypes.windll.kernel32.GetFileAttributesW(folder_path) & 0x4 == 0x4

def copy_file(src_file_path, dest_file_path, status_text):
    try:
        shutil.copy2(src_file_path, dest_file_path)
        status_text.insert(END, f"Copied file: {dest_file_path}\n")
        status_text.see(END)
        status_text.update()
    except Exception as e:
        status_text.insert(END, f"Error copying file {src_file_path} to {dest_file_path}: {e}\n")
        status_text.see(END)
        status_text.update()

def remove_excess_files_and_dirs(src, dest, status_text, remove_excess):
    global deleted_count

    if not remove_excess:
        return

    for dest_root, dest_dirs, dest_files in os.walk(dest, topdown=False):
        src_root = os.path.join(src, os.path.relpath(dest_root, dest))

        for dest_file in dest_files:
            src_file_path = os.path.join(src_root, dest_file)
            dest_file_path = os.path.join(dest_root, dest_file)

            if not os.path.exists(src_file_path) and has_admin_permission(dest_file_path):
                try:
                    os.remove(dest_file_path)
                    deleted_count += 1
                    status_text.insert(END, f"Removed excess file: {dest_file_path}\n")
                    status_text.see(END)
                    status_text.update()
                except Exception as e:
                    status_text.insert(END, f"Error removing excess file {dest_file_path}: {e}\n")
                    status_text.see(END)
                    status_text.update()

        for dest_dir in dest_dirs:
            src_dir_path = os.path.join(src_root, dest_dir)
            dest_dir_path = os.path.join(dest_root, dest_dir)

            if not os.path.exists(src_dir_path) and not is_system_directory(dest_dir_path) and has_admin_permission(dest_dir_path):
                try:
                    shutil.rmtree(dest_dir_path)
                    deleted_count += 1
                    status_text.insert(END, f"Removed excess directory: {dest_dir_path}\n")
                    status_text.see(END)
                    status_text.update()
                except Exception as e:
                    status_text.insert(END, f"Error removing excess directory {dest_dir_path}: {e}\n")
                    status_text.see(END)
                    status_text.update()

            elif os.path.exists(src_dir_path) and dest_dir in dest_dirs:
                dest_dirs.remove(dest_dir)

def sync_directories(src, dest, status_text, progress_bar, use_hash, remove_excess):
    copied_count = 0
    global deleted_count
    deleted_count = 0

    if not os.path.exists(src) or not os.path.exists(dest):
        messagebox.showerror("Error", "Both source and destination directories must exist.")
        return copied_count, deleted_count

    try:
        with ThreadPoolExecutor() as executor:
            for src_root, src_dirs, src_files in os.walk(src):
                dest_root = os.path.join(dest, os.path.relpath(src_root, src))

                for src_dir in src_dirs:
                    if stop_sync_flag:
                        break
                    
                    dest_dir = os.path.join(dest_root, src_dir)
                    if not os.path.exists(dest_dir):
                        try:
                            os.makedirs(dest_dir)
                            copied_count += 1
                            root.after_idle(status_text.insert, END, f"Created directory: {dest_dir}\n")
                            root.after_idle(status_text.see, END)
                        except Exception as e:
                            root.after_idle(status_text.insert, END, f"Error creating directory {dest_dir}: {e}\n")
                            root.after_idle(status_text.see, END)

                for src_file in src_files:
                    if stop_sync_flag:
                        break
                    
                    src_file_path = os.path.join(src_root, src_file)
                    dest_file_path = os.path.join(dest_root, src_file)
                    if should_copy(src_file_path, dest_file_path, use_hash.get(), compare_mod_date.get()):
                        copied_count += 1
                        executor.submit(copy_file, src_file_path, dest_file_path, status_text)

                    # Update the current source file path label
                    truncated_src_file_path = src_file_path[:50] + (src_file_path[50:] and '...')
                    root.after_idle(current_file_var.set, f"{truncated_src_file_path}")

                    if stop_sync_flag:
                        root.after_idle(status_text.insert, END, "Synchronization stopped by user.\n")
                        root.after_idle(status_text.see, END)
                        return copied_count, deleted_count

                    time.sleep(0.01)  # Smoother progress_bar update

        remove_excess_files_and_dirs(src, dest, status_text, remove_excess.get())

    except Exception as e:
        root.after_idle(status_text.insert, END, f"Error during synchronization: {e}\n")
        root.after_idle(status_text.see, END)
    finally:
        progress_bar.stop()
        progress_bar.grid_forget()

    return copied_count, deleted_count

def start_sync():
    src = src_folder_path.get()
    dest = dest_folder_path.get()

    if not src or not dest:
        messagebox.showerror("Error", "Both source and destination directories must be specified.")
        return

    global stop_sync_flag
    stop_sync_flag = False

    status_text.delete(1.0, END)
    status_text.insert(END, "Synchronization started...\n")
    status_text.see(END)
    status_text.update()

    progress_bar.grid(column=1, row=4, sticky=(E, W))
    root.after(100, lambda: update_progress_bar(progress_bar))
    update_progress_bar(progress_bar)

    copied_count, deleted_count = sync_directories(src, dest, status_text, progress_bar, use_hash, remove_excess)

    status_text.insert(END, f"\nSynchronization finished. {copied_count} items copied, {deleted_count} items removed.\n")
    status_text.see(END)

def stop_sync():
    sync_app.stop_sync_flag = True
    global stop_sync_flag
    stop_sync_flag = True

root = Tk()
root.title("Directory Synchronization")

current_file_var = StringVar()

mainframe = ttk.Frame(root, padding="12 12 12 12")
mainframe.grid(column=0, row=0, sticky=(N, S, E, W))

src_folder_path = StringVar()
dest_folder_path = StringVar()
use_hash = BooleanVar(value=False)
remove_excess = BooleanVar(value=True)
compare_mod_date = BooleanVar(value=True)

ttk.Label(mainframe, text="Source directory:").grid(column=0, row=0, sticky=W)
src_folder_entry = ttk.Entry(mainframe, width=50, textvariable=src_folder_path)
src_folder_entry.grid(column=1, row=0, sticky=(E, W))
ttk.Button(mainframe, text="Browse", command=browse_src_directory).grid(column=2, row=0, sticky=W)

ttk.Label(mainframe, text="Destination directory:").grid(column=0, row=1, sticky=W)
dest_folder_entry = ttk.Entry(mainframe, width=50, textvariable=dest_folder_path)
dest_folder_entry.grid(column=1, row=1, sticky=(E, W))
ttk.Button(mainframe, text="Browse", command=browse_dest_directory).grid(column=2, row=1, sticky=W)

ttk.Checkbutton(mainframe, text="Use xxhash to compare files", variable=use_hash).grid(column=1, row=2, sticky=W)
ttk.Checkbutton(mainframe, text="Remove excess files and directories at the destination", variable=remove_excess).grid(column=1, row=3, sticky=W)
ttk.Checkbutton(mainframe, text="Compare and copy files by modified date", variable=compare_mod_date).grid(column=1, row=4, sticky=W)

start_button = ttk.Button(mainframe, text="Start", command=start_sync_thread)
start_button.grid(column=0, row=4, sticky=W)

progress_bar = ttk.Progressbar(mainframe, mode='indeterminate')
progress_bar.grid(column=1, row=4, sticky=(E, W))
progress_bar.grid_remove()

stop_button = ttk.Button(mainframe, text="Stop", command=stop_sync)
stop_button.grid(column=2, row=4, sticky=W)

current_file_label = ttk.Label(mainframe, textvariable=current_file_var)
current_file_label.grid(column=1, row=6, sticky=W)

current_src_file_path = StringVar()
current_src_file_label = ttk.Label(mainframe, textvariable=current_src_file_path)
status_label = ttk.Label(mainframe, text="Status:")
status_label.grid(column=0, row=6, sticky=W)


status_text = Text(mainframe, wrap="word", width=50, height=10)
status_text.grid(column=1, row=5, sticky=(N, S, E, W))
status_scroll = ttk.Scrollbar(mainframe, orient="vertical", command=status_text.yview)
status_scroll.grid(column=2, row=5, sticky=(N, S, W))
status_text["yscrollcommand"] = status_scroll.set

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)
mainframe.rowconfigure(5, weight=1)

sizegrip = Sizegrip(mainframe)
sizegrip.grid(column=2, row=6, sticky=(S, E))

root.mainloop()
