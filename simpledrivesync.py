import os
import shutil
import threading
import ctypes
import hashlib
from tkinter import filedialog, messagebox, Tk, Button, Label, Entry, StringVar, Text, Scrollbar, END, N, S, E, W, Frame
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor

stop_sync_flag = False
deleted_count = 0

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
    if stop_sync_flag:
        progress_bar.stop()
        progress_bar.grid_forget()
        return
    progress_bar.step(10)
    progress_bar.after(100, lambda: update_progress_bar(progress_bar))

def should_copy(src_file_path, dest_file_path):
    if not os.path.exists(dest_file_path):
        return True

    if os.path.getsize(src_file_path) != os.path.getsize(dest_file_path):
        return True

    chunk_size = 1024 * 1024 # 1 MB
    with open(src_file_path, 'rb') as src_file, open(dest_file_path, 'rb') as dest_file:
        while True:
            src_chunk = src_file.read(chunk_size)
            dest_chunk = dest_file.read(chunk_size)
            if src_chunk != dest_chunk:
                return True
            if not src_chunk:
                break

    return False

def is_system_directory(folder_path):
    return os.path.isdir(folder_path) and ctypes.windll.kernel32.GetFileAttributesW(folder_path) & 0x4 == 0x4

def remove_excess_files_and_dirs(src, dest, status_text):
    global deleted_count

    for dest_root, dest_dirs, dest_files in os.walk(dest, topdown=False):
        src_root = os.path.join(src, os.path.relpath(dest_root, dest))

        for dest_file in dest_files:
            src_file_path = os.path.join(src_root, dest_file)
            dest_file_path = os.path.join(dest_root, dest_file)

            # Check if the file exists in the source directory before deleting it
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

            # Check if the directory exists in the source directory before deleting it
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

            # If the directory exists in the source directory, remove it from the dest_dirs list to avoid
            # removing it later in the loop
            elif os.path.exists(src_dir_path) and dest_dir in dest_dirs:
                dest_dirs.remove(dest_dir)

def sync_directories(src, dest, status_text, progress_bar):
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
                    dest_dir = os.path.join(dest_root, src_dir)
                    if not os.path.exists(dest_dir):
                        try:
                            os.makedirs(dest_dir)
                            copied_count += 1
                            status_text.insert(END, f"Created directory: {dest_dir}\n")
                            status_text.see(END)
                            status_text.update()
                        except Exception as e:
                            status_text.insert(END, f"Error creating directory {dest_dir}: {e}\n")
                            status_text.see(END)
                            status_text.update()

                for src_file in src_files:
                    if stop_sync_flag:
                        break
                    src_file_path = os.path.join(src_root, src_file)
                    dest_file_path = os.path.join(dest_root, src_file)
                    if should_copy(src_file_path, dest_file_path):
                        copied_count += 1
                        executor.submit(copy_file, src_file_path, dest_file_path, status_text)

                if stop_sync_flag:
                    status_text.insert(END, "Synchronization stopped by user.\n")
                    status_text.see(END)
                    status_text.update()
                    return copied_count, deleted_count

        remove_excess_files_and_dirs(src, dest, status_text)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during synchronization: {e}")

    status_text.insert(END, f"Synchronization completed. {copied_count} files/directories copied, {deleted_count} files/directories deleted.\n")
    progress_bar.grid_forget()
    status_text.see(END)
    status_text.update()

    return copied_count, deleted_count

def start_sync(status_text, progress_bar):
    global stop_sync_flag
    stop_sync_flag = False

    src = src_folder_path.get()
    dest = dest_folder_path.get()

    if not src or not dest:
        messagebox.showerror("Error", "Both source and destination directories must be selected.")
        return

    status_text.delete('1.0', END)

    progress_bar.grid(row=4, column=2, padx=5, pady=5)
    progress_bar.start()
    update_progress_bar(progress_bar)

    sync_thread = threading.Thread(target=lambda: sync_directories(src, dest, status_text, progress_bar))
    sync_thread.start()


def stop_sync():
    global stop_sync_flag
    stop_sync_flag = True

def main():
    global src_folder_path, dest_folder_path

    root = Tk()
    root.title("Drive Synchronization Tool")
    root.geometry("800x600")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(7, weight=1)

    src_folder_path = StringVar()
    dest_folder_path = StringVar()

    src_label = Label(root, text="Source Directory:")
    src_label.grid(row=0, column=0, sticky=W, padx=5, pady=5)

    src_entry = Entry(root, textvariable=src_folder_path, width=50)
    src_entry.grid(row=1, column=0, sticky=W, padx=5)

    src_browse_button = Button(root, text="Browse Source", command=browse_src_directory)
    src_browse_button.grid(row=1, column=1, sticky=W, padx=5)

    dest_label = Label(root, text="Destination Directory:")
    dest_label.grid(row=2, column=0, sticky=W, padx=5, pady=5)

    dest_entry = Entry(root, textvariable=dest_folder_path, width=50)
    dest_entry.grid(row=3, column=0, sticky=W, padx=5)

    dest_browse_button = Button(root, text="Browse Destination", command=browse_dest_directory)
    dest_browse_button.grid(row=3, column=1, sticky=W, padx=5)

    sync_button = Button(root, text="Start Sync", command=lambda: start_sync(status_text, progress_bar))
    sync_button.grid(row=4, column=0, pady=10)

    stop_button = Button(root, text="Stop Sync", command=stop_sync)
    stop_button.grid(row=4, column=1, pady=10)

    progress_bar_frame = Frame(root)
    progress_bar_frame.grid(row=5, column=0, columnspan=2)

    progress_bar = ttk.Progressbar(progress_bar_frame, mode='indeterminate', length=200)
    progress_bar.pack(pady=10)
    progress_bar.pack_forget()

    status_label = Label(root, text="Synchronization Status:")
    status_label.grid(row=6, column=0, sticky=W, padx=5, pady=5)

    status_text = Text(root, wrap='word')
    status_text.grid(row=7, column=0, columnspan=2, rowspan=2, sticky=N + S + E + W, padx=5, pady=5)

    scrollbar = Scrollbar(root, command=status_text.yview)
    scrollbar.grid(row=7, column=2, rowspan=2, sticky=N + S)

    status_text.config(yscrollcommand=scrollbar.set)

    sizegrip = ttk.Sizegrip(root)
    sizegrip.grid(row=9, column=2, sticky=E + S)

    root.mainloop()

if __name__ == "__main__":
    main()
