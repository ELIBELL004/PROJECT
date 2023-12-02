import tkinter as tk
import nmap
import vulnerability_scanner

def scan_network():
    network_range = entry_network_range.get()
    report = vulnerability_scanner.scan_network(network_range)
    text_report.insert(tk.END, report)

window = tk.Tk()
window.title("Vulnerability Scanner")

label_network_range = tk.Label(window, text="Network Range:")
entry_network_range = tk.Entry(window)

button_scan = tk.Button(window, text="Scan Network", command=scan_network)
text_report = tk.Text(window)

label_network_range.pack()
entry_network_range.pack()
button_scan.pack()
text_report.pack()

window.mainloop()