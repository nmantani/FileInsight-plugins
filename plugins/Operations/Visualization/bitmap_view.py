#
# Bitmap view - Visualize the whole file as bitmap representation
#
# Copyright (c) 2021, Nobutaka Mantani
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import threading
import tkinter
import tkinter.ttk

try:
    from PIL import Image, ImageDraw, ImageTk
except ImportError:
    sys.exit(-1) # Pillow is not installed

def render_bitmap(start, end, force):
    global data, width, canvas, list_image, list_imagetk, list_canvas, list_rendered, color_dict, bg_color, thread_event, abort

    if start < 0:
        start = 0
    if end > (len(data) // (width * width)) + 1:
        end = (len(data) // (width * width)) + 1

    bytes_rendered = start * width * width
    height_rendered = start * width

    for n in range(start, end):
        # Abort rendering if window is closed
        if abort == True:
            return

        # Pause rendering while dragging canvas
        thread_event.wait()

        # Skip already rendered region
        if list_rendered[n] == True and force == False:
            continue

        remain = len(data) - bytes_rendered
        if remain // width < width:
            unit_height = remain // width
        else:
            unit_height = width

        bg_color = "white"
        image = Image.new(mode="RGB", size=(width, unit_height))
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, width, unit_height), fill=color_dict[bg_color], outline=color_dict[bg_color])

        for i in range(width * height_rendered, (width * height_rendered) + (width * unit_height)):
            # Abort rendering if window is closed
            if abort == True:
                return

            x = i % width
            y = (i // width) - height_rendered

            if data[i] == 0:
                if bg_color != "white":
                    image.putpixel((x, y), color_dict["white"])
            elif data[i] < 0x20 or data[i] == 0x7f:
                if bg_color != "blue":
                    image.putpixel((x, y), color_dict["blue"])
            elif data[i] < 0x80:
                if bg_color != "red":
                    image.putpixel((x, y), color_dict["red"])
            elif data[i] >= 0x80:
                if bg_color != "black":
                    image.putpixel((x, y), color_dict["black"])

        try:
            imagetk = ImageTk.PhotoImage(image=image)

            if unit_height < width:
                can = canvas.create_image(0, height_rendered - ((width - unit_height) // 2) - 1, image=imagetk)
            else:
                can = canvas.create_image(0, height_rendered, image=imagetk)
        except:
            pass # Ignore exception on closing window

        # Retain rendered images to avoid garbage collection
        list_image.append(image)
        list_imagetk.append(imagetk)
        list_canvas.append(can)

        bytes_rendered += width * unit_height
        height_rendered += unit_height
        list_rendered[n] = True

def window_close_event(root):
    global abort

    abort = True
    root.quit()

def scroll_event(*args):
    global canvas, scrollbar, scrollbar_dragging, num_images, current_position

    canvas.yview(*args)

    # Start rendering around current position
    if scrollbar_dragging == False and args[0] == "scroll" and args[2] == "pages":
        (start, end) = scrollbar.get()
        current_position = int(start * num_images)
        render_bitmap(current_position - 5, current_position + 10, False)

def scrollbar_motion_event(*args):
    global scrollbar_dragging

    scrollbar_dragging = True

def scrollbar_release_event(*args):
    global scrollbar, scrollbar_dragging, num_images, current_position

    # Start rendering around current position
    if scrollbar_dragging == True:
        (start, end) = scrollbar.get()
        current_position = int(start * num_images)
        render_bitmap(current_position - 5, current_position + 10, False)
        scrollbar_dragging = False

def canvas_mousewheel_event(event):
    global canvas, scrollbar, label_offset, label_value, width, height, data

    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    # Origin of canvas is (-64, -64)
    x = canvas.canvasx(event.x) + 64
    if x < 0:
        x = 0
    elif x > width:
        x = width

    y = canvas.canvasy(event.y) + 64
    if y < 0:
        y = 0
    elif y > height:
        y = height

    # Update labels of offset and value
    offset = int(x + (width * y))
    if offset < len(data):
        label_offset.configure(text="Offset: %s" % hex(offset))
        label_value.configure(text="Value: %s" % hex(data[offset]))
    else:
        label_offset.configure(text="Offset: ")
        label_value.configure(text="Value: ")

def canvas_press_event(event):
    global canvas_x, canvas_y, thread_event

    # Pause rendering
    canvas_x = event.x
    canvas_y = event.y
    thread_event.clear()

def canvas_release_event(event):
    global canvas_x, canvas_y, thread_event

    # Resume rendering
    canvas_x = None
    canvas_y = None
    thread_event.set()

def canvas_drag_motion_event(event):
    global root, canvas_x, canvas_y, thread

    delta_x = event.x - canvas_x
    delta_y = event.y - canvas_y

    # Move window by dragging canvas
    new_x = root.winfo_x() + delta_x
    new_y = root.winfo_y() + delta_y
    root.geometry("+%d+%d" % (new_x, new_y))

def canvas_motion_event(event):
    global canvas, label_offset, label_value, width, height, data

    # Origin of canvas is (-64, -64)
    x = canvas.canvasx(event.x) + 64
    if x < 0:
        x = 0
    elif x > width:
        x = width

    y = canvas.canvasy(event.y) + 64
    if y < 0:
        y = 0
    elif y > height:
        y = height

    # Update labels of offset and value
    offset = int(x + (width * y))
    if offset < len(data):
        label_offset.configure(text="Offset: %s" % hex(offset))
        label_value.configure(text="Value: %s" % hex(data[offset]))
    else:
        label_offset.configure(text="Offset: ")
        label_value.configure(text="Value: ")

def show_context_menu(event):
    global menu

    menu.post(event.x_root,event.y_root)

def copy_offset():
    global root, label_offset

    offset = label_offset.cget("text")[8:]
    root.clipboard_clear()
    root.clipboard_append(offset)

color_dict = {"white": (255, 255, 255),
              "blue": (0, 0, 255),
              "red": (255, 0, 0),
              "black": (0, 0, 0)}

if sys.argv[1] == "-c":
    sys.exit(0) # Do nothing, only checking existence of Pillow

# Receive data
filename = sys.argv[1]
with open(filename, "rb") as f:
    data = f.read()

# Create window
root = tkinter.Tk()
root.title("Bitmap view")
root.protocol("WM_DELETE_WINDOW", (lambda root=root: window_close_event(root)))

# Size of bitmap image
width = 128
height = (len(data) // width) + 1
num_images = (len(data) // (width * width)) + 1
current_position = 0

# Set canvas resizable
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# labels for legends
label_image1 = Image.new(mode="RGB", size=(12, 12))
label_draw1 = ImageDraw.Draw(label_image1)
label_draw1.rectangle((0, 0, 11, 11), fill=color_dict["white"], outline=color_dict["black"])
label_imagetk1 = ImageTk.PhotoImage(image=label_image1)
label1 = tkinter.Label(text=" 0x00", image=label_imagetk1, compound="left", height=12)
label1.grid(row=1, column=0, padx=0, pady=0, sticky="w", columnspan=2)

label_image2 = Image.new(mode="RGB", size=(12, 12))
label_draw2 = ImageDraw.Draw(label_image2)
label_draw2.rectangle((0, 0, 12, 12), fill=color_dict["blue"], outline=color_dict["blue"])
label_imagetk2 = ImageTk.PhotoImage(image=label_image2)
label2 = tkinter.Label(text=" ASCII control", image=label_imagetk2, compound="left", height=12)
label2.grid(row=2, column=0, padx=0, pady=0, sticky="w", columnspan=2)

label_image3 = Image.new(mode="RGB", size=(12, 12))
label_draw3 = ImageDraw.Draw(label_image3)
label_draw3.rectangle((0, 0, 12, 12), fill=color_dict["red"], outline=color_dict["red"])
label_imagetk3 = ImageTk.PhotoImage(image=label_image3)
label3 = tkinter.Label(text=" ASCII printable", image=label_imagetk3, compound="left", height=12)
label3.grid(row=3, column=0, padx=0, pady=0, sticky="w", columnspan=2)

label_image4 = Image.new(mode="RGB", size=(12, 12))
label_draw4 = ImageDraw.Draw(label_image4)
label_draw4.rectangle((0, 0, 12, 12), fill=color_dict["black"], outline=color_dict["black"])
label_imagetk4 = ImageTk.PhotoImage(image=label_image4)
label4 = tkinter.Label(text=" Non-ASCII (>= 0x80)", image=label_imagetk4, compound="left", height=12)
label4.grid(row=4, column=0, padx=0, pady=0, sticky="w", columnspan=2)

# Label to show offset of data on current mouse cursor position
label_offset = tkinter.Label(text="Offset: ")
label_offset.grid(row=5, column=0, padx=0, pady=0, sticky="w", columnspan=2)

# Label to show value of data on current mouse cursor position
label_value = tkinter.Label(text="Value: ")
label_value.grid(row=6, column=0, padx=0, pady=0, sticky="w", columnspan=2)

# Create canvas
canvas = tkinter.Canvas(root, width=width, height=width*3, scrollregion=(0,0,width,height), bg="#ffffff")
canvas.grid(row=0, column=0, sticky="nsew")

# Lists to retain rendered bitmap images
list_image = []
list_imagetk = []
list_canvas = []
list_rendered = [False] * num_images

# Start rendering from top
abort = False
thread_event = threading.Event()
thread_event.set()
thread = threading.Thread(target=render_bitmap, args=(0, num_images, True))
thread.start()

scrollbar = tkinter.Scrollbar(root, orient="vertical", command=scroll_event)
scrollbar.grid(row=0, column=1, sticky="ns")

# Event handlers for scrollbar
scrollbar_dragging = False
scrollbar.bind("<Button1-Motion>", scrollbar_motion_event)
scrollbar.bind("<ButtonRelease-1>", scrollbar_release_event)

# Connect canvas and scrollbar
canvas.configure(yscrollcommand=scrollbar.set)
canvas.configure(scrollregion=(-64, -64, 64, height - 64))

# Context menu of canvas
menu = tkinter.Menu(root, tearoff=False)
menu.add_command(label="Copy offset to clipboard", command=copy_offset)

# Show top of canvas
canvas.yview_moveto(0)

# Event handlers for canvas
canvas.bind_all("<MouseWheel>", canvas_mousewheel_event)
canvas.bind("<ButtonPress-1>", canvas_press_event)
canvas.bind("<ButtonRelease-1>", canvas_release_event)
canvas.bind("<Button1-Motion>", canvas_drag_motion_event)
canvas.bind("<Motion>", canvas_motion_event)
canvas.bind('<Button-3>', show_context_menu)

# Coordinates in canvas
canvas_x = None
canvas_y = None

# Adjust window position
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
root.geometry("+%d+%d" % ((w/8), (h/16)))
root.resizable(width=False, height=True)

root.mainloop()

# Remove temporary file on exit
os.remove(filename)
