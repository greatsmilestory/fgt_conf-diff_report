import re
import html
import json
import webbrowser
import os

# tkinter import and fallback handling
try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
    print("Warning: tkinter is not available. Running in manual file path input mode.")

    # =========================
    # File Selection
    # =========================
def select_files():
    if not TKINTER_AVAILABLE:
        print("Since tkinter is not available, please enter the file paths manually:")
        return manual_file_input()

    try:
        # tkinter environment setup
        root = tk.Tk()
        root.withdraw()  # Hide the main window

        # Fix for window hiding behind others on Windows
        root.wm_attributes('-topmost', 1)
        root.after_idle(lambda: root.wm_attributes('-topmost', 0))

        # File selection dialog
        file_paths = filedialog.askopenfilenames(
            title="Select FortiGate Config Files",
            filetypes=[
                ("Config files", "*.conf *.txt"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ],
            parent=root
        )

        root.destroy()  # Explicitly destroy the root window
        return list(file_paths)

    except Exception as e:
        print(f"GUI file selection error: {e}")
        print("Switching to manual input mode...")
        return manual_file_input()

def manual_file_input():
    """Function to receive file paths manually"""
    print("\n=== Manual File Path Input ===")
    print("Enter the full path of the FortiGate configuration file.")
    print("Example: C:\\configs\\FGT_firewall.conf")
    print("To add multiple files, enter them one by one. Enter a blank line when finished.")

    files = []
    while True:
        file_path = input(f"\nFile path {len(files)+1} (Press Enter to finish): ").strip().strip('"')
        if not file_path:
            break
        if os.path.exists(file_path):
            files.append(file_path)
            print(f"✓ Added: {os.path.basename(file_path)}")
        else:
            print(f"✗ File not found: {file_path}")
            retry = input("Would you like to try again? (y/n): ").lower()
            if retry != 'y':
                continue

    return files

# =========================
# VDOM Detection and Parsing
# =========================
def is_single_vdom(config_text):
    return "config vdom" not in config_text

def extract_firewall_objects(text):
    firewall_pattern = re.compile(r'(config firewall .+?)(?=config|end\s+config|\Z)', re.S)
    object_pattern = re.compile(r'edit "(.+?)"(.*?)next', re.S)
    set_pattern = re.compile(r'set (\S+) (.+)')

    firewalls = {}
    for fw_block in firewall_pattern.findall(text):
        fw_type = fw_block.split("\n")[0].strip()
        objects = {}
        for obj_name, obj_content in object_pattern.findall(fw_block):
            props = {}
            for key, val in set_pattern.findall(obj_content):
                if key.lower() in ["uuid"]:
                    continue
                if key.lower() == "member":
                    items = re.findall(r'"([^"]*)"', val)
                    val = " ".join(f'"{item}"' for item in sorted(items))
                else:
                    val = val.strip('"')
                    if key.lower() == "comment":
                        val = " ".join(val.split())
                props[key] = val
            objects[obj_name] = props
        firewalls[fw_type] = objects
    return firewalls

def parse_config_file(file_path):
    with open(file_path, encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    single = is_single_vdom(config_text)
    vdom_data = {}

    if single:
        vdom_name = "root"
        vdom_data[vdom_name] = extract_firewall_objects(config_text)
    else:
        vdom_start_pattern = re.compile(r'edit (\S+)\s+config system object-tagging', re.S)
        matches = list(vdom_start_pattern.finditer(config_text))
        for idx, match in enumerate(matches):
            vdom_name = match.group(1)
            start_pos = match.start()
            end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(config_text)
            vdom_content = config_text[start_pos:end_pos]
            vdom_data[vdom_name] = extract_firewall_objects(vdom_content)

    return single, vdom_data

# =========================
# Comparison/Highlighting Logic
# =========================
def compare_objects_across_files(file_vdom_map):
    all_objects = {}  # (fw_type, obj_name) => {label: props}
    col_labels = []   # e.g., "filename\n[VDOM]"

    # Creation order: File → VDOM
    for file_path, vdoms in file_vdom_map.items():
        file_label = os.path.basename(file_path)
        for vdom in vdoms.keys():
            label = f"{file_label}\n[{vdom}]"
            col_labels.append(label)

    # Collect objects
    for file_path, vdoms in file_vdom_map.items():
        file_label = os.path.basename(file_path)
        for vdom, fw_types in vdoms.items():
            label = f"{file_label}\n[{vdom}]"
            for fw_type, objects in fw_types.items():
                for obj_name, props in objects.items():
                    key = (fw_type, obj_name)
                    if key not in all_objects:
                        all_objects[key] = {}
                    all_objects[key][label] = props

    # Extract differences only
    diffs = {}
    # Property display order
    PROPERTY_ORDER = [
        'interface', 'associated-interface', 'type', 'subnet', 'start-ip', 'end-ip', 'fqdn',
        'protocol', 'tcp-portrange', 'udp-portrange', 'icmptype', 'icmpcode',
        'sctp-portrange', 'protocol-number', 'iprange', 'category',
        'member', 'exclude-member', 'visibility',
        'comment', 'color', 'fabric-object', 'allow-routing',
    ]

    def get_property_sort_key(prop):
        if prop in PROPERTY_ORDER:
            return (0, PROPERTY_ORDER.index(prop), prop)
        else:
            return (1, 0, prop)

    for (fw_type, obj_name), label_props in all_objects.items():
        all_props = {}
        for props in label_props.values():
            for p in props.keys():
                all_props[p] = True

        obj_diff = {}
        sorted_props = sorted(all_props.keys(), key=get_property_sort_key)

        for prop in sorted_props:
            values = {}
            valid_labels = [label for label in col_labels if label in label_props]
            for label in valid_labels:
                val = label_props.get(label, {}).get(prop, "")
                if val is None:
                    val = ""
                values[label] = val

            if len(values) < 2:
                continue
            if len(set(values.values())) <= 1:
                continue

            obj_diff[prop] = values

        if obj_diff:
            diffs[(fw_type, obj_name)] = obj_diff

    return all_objects, col_labels, diffs

# =========================
# Highlight Helper
# =========================
def highlight_differences_across_vdoms(values):
    vdom_items = {}
    item_count = {}

    for vdom, val in values.items():
        if val is None or val == "":
            vdom_items[vdom] = []
        else:
            if '"' in val:
                items = re.findall(r'"([^"]*)"', val)
            else:
                items = [val]
            vdom_items[vdom] = items
            for item in items:
                item_count[item] = item_count.get(item, 0) + 1

    DUPLICATE_COLORS = [
        "#ffff99", "#ccffcc", "#99ccff", "#ffcc99",
        "#ff99cc", "#ccccff", "#ffd699", "#c2f0c2",
        "#b3e6ff", "#ffb3b3", "#d9b3ff", "#ffffb3",
        "#66ff66", "#66ccff", "#ff6666", "#ffcc00",
        "#9966ff", "#66ffff", "#ff9966", "#66ffcc",
        "#ff66cc", "#99ff66", "#3399ff", "#ffcc66",
        "#cc99ff", "#99ffff", "#ff9999", "#ccff66",
        "#66b3ff", "#ff66ff", "#aaffaa", "#ffb366",
        "#c299ff", "#99ffcc", "#ff6699", "#b3ff66"
    ]
    color_map = {}
    color_index = 0
    for item in sorted(item_count.keys()):
        if item_count[item] >= 2:
            color_map[item] = DUPLICATE_COLORS[color_index % len(DUPLICATE_COLORS)]
            color_index += 1

    highlighted_values = {}
    duplicate_items = set(item for item, count in item_count.items() if count >= 2)

    for vdom, items in vdom_items.items():
        highlighted_parts = []
        for item in items:
            if item in color_map:
                highlighted_parts.append(f'<span style="background-color:{color_map[item]}">"{item}"</span>')
            else:
                highlighted_parts.append(f'<span style="background-color:#ff6666">"{item}"</span>')
        highlighted_values[vdom] = "<br>".join(highlighted_parts) if highlighted_parts else ""

    return highlighted_values, duplicate_items

def wrap_hover_spans_with_color(text, group_id, duplicate_items):
    span_pattern = re.compile(r'(<span style="background-color:[^"]+">"([^"]*)"</span>)')
    out, idx = [], 0
    for m in span_pattern.finditer(text):
        s, e = m.span()
        if s > idx:
            out.append(text[idx:s])
        full_span, val = m.group(1), m.group(2)
        if val in duplicate_items:
            out.append(f'<span class="hover-item" data-val="{html.escape(val)}" data-row="{group_id}">{full_span}</span>')
        else:
            out.append(full_span)
        idx = e
    if idx < len(text):
        out.append(text[idx:])
    return "".join(out)

# =========================
# Table Generation Function
# =========================
def generate_table_content(all_objects, col_labels, diffs):
    """Generate table content with filtered data"""
    table_content = ""
    row_num = 1
    total_rows = 0

    for (fw_type, obj_name), prop_diffs in sorted(diffs.items(), key=lambda x: (x[0][0], x[0][1].lower())):
        prop_list = list(prop_diffs.items())
        rowspan = len(prop_list)
        group_class = "group-even" if (row_num % 2 == 0) else "group-odd"

        for idx2, (prop, values) in enumerate(prop_list):
            total_rows += 1

            table_content += (f'<tr class="row-group {group_class}" '
                              f'data-group="{row_num}" '
                              f'data-fw-type="{html.escape(fw_type)}">')

            if idx2 == 0:
                table_content += f'<td class="rownum" rowspan="{rowspan}">{row_num}</td>'
                table_content += f'<td class="type" rowspan="{rowspan}">{html.escape(fw_type)}</td>'
                table_content += f'<td class="objname" rowspan="{rowspan}">{html.escape(obj_name)}</td>'
            table_content += f'<td class="property">{html.escape(prop)}</td>'

            highlighted_vals, duplicate_items = highlight_differences_across_vdoms(values)

            for label in col_labels:
                val = values.get(label, "")
                obj_props = all_objects.get((fw_type, obj_name), {}).get(label, None)
                if obj_props is None:
                    cell_text = "Object missing"
                    cell_class = "missing-object"
                elif val == "":
                    cell_text = "No property value"
                    cell_class = "missing-value"
                else:
                    colored_val = highlighted_vals.get(label, "")
                    cell_text = wrap_hover_spans_with_color(colored_val, row_num, duplicate_items)
                    cell_class = ""
                table_content += f'<td class="vdom-column {cell_class}">{cell_text}</td>'
            table_content += "</tr>"
        row_num += 1

    return table_content, total_rows

# =========================
# HTML Generation (with multi-filter tag system)
# =========================
def generate_html_report(all_objects, col_labels, diffs, output_file="report_fgt_diff_addr_service.html"):
    colors = [
        "#1976D2", "#388E3C", "#FBC02D", "#F57C00",
        "#7B1FA2", "#00796B", "#C2185B", "#303F9F",
        "#FFA000", "#5D4037", "#455A64", "#D32F2F"
    ]

    # Filename → color mapping
    file_names = []
    file_name_to_color = {}
    for label in col_labels:
        fname = label.split("\n")[0]
        if fname not in file_names:
            file_names.append(fname)
    for i, fname in enumerate(file_names):
        file_name_to_color[fname] = colors[i % len(colors)]

    # Column label (file-based) background colors
    label_colors = {}
    def get_contrast_color(bgcolor):
        bg = bgcolor.lstrip('#')
        r, g, b = int(bg[0:2], 16), int(bg[2:4], 16), int(bg[4:6], 16)
        brightness = (r * 299 + g * 587 + b * 114) / 1000
        return "#000000" if brightness > 150 else "#ffffff"
    for label in col_labels:
        fname = label.split("\n")[0]
        label_colors[label] = file_name_to_color.get(fname, "#ffffff")

    # Collect all unique types and properties (for filter options)
    all_types = set()
    all_properties = set()
    for (fw_type, obj_name), prop_diffs in diffs.items():
        all_types.add(fw_type)
        for prop in prop_diffs.keys():
            all_properties.add(prop)

    # Generate initial table content
    initial_table_content, _ = generate_table_content(all_objects, col_labels, diffs)
    initial_total_rows = initial_table_content.count('<td class="rownum"')

    # Start of HTML
    html_content = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>FGT config files VDOM object comparison</title>
<style>
:root {
  --bg: #f7f8fa;
  --text: #111111;
  --muted: #5a5f6a;
  --surface: #ffffff;
  --border: #e5e7eb;
  --accent: #3b82f6;
  --accent-weak: #e8f0fe;
  --radius: 10px;
  --shadow: 0 4px 14px rgba(0,0,0,0.06);
  --toolbar-height: 130px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0d10;
    --text: #e5e7eb;
    --muted: #9aa0a6;
    --surface: #15181d;
    --border: #252a33;
    --accent: #60a5fa;
    --accent-weak: #1e3a8a;
    --shadow: 0 6px 18px rgba(0,0,0,0.35);
  }
}

html, body {
  padding: 0; margin: 0; height: 100vh;
  background: var(--bg); color: var(--text);
  font-family: Inter, "Noto Sans KR", system-ui, -apple-system, Segoe UI, Roboto, "Malgun Gothic", Arial, sans-serif;
  font-size: 14px; line-height: 1.6;
  -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
  overflow: hidden;
}

.credit {
  position: fixed;
  top: 12px;
  right: 12px;
  z-index: 1000;
  font-size: 10px;
  color: var(--muted);
  background: rgba(255, 255, 255, 0.9);
  padding: 4px 8px;
  border-radius: 4px;
  backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  user-select: none;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.2s ease;
}

.credit:hover {
  background: rgba(255, 255, 255, 0.95);
  color: var(--accent);
  border-color: var(--accent);
}

@media (prefers-color-scheme: dark) {
  .credit { background: rgba(13, 16, 22, 0.9); }
  .credit:hover { background: rgba(13, 16, 22, 0.95); }
}

.container {
  width: 100%;
  height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 16px;
  box-sizing: border-box;
  gap: 12px;
}

h3 { 
  margin: 0; 
  font-size: 18px; 
  font-weight: 700; 
  flex-shrink: 0;
}

#toolbar {
  flex-shrink: 0;
  min-height: 60px;
  background: rgba(255,255,255,0.95);
  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 16px;
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: 12px;
  transition: all 0.3s ease;
  position: relative;
  z-index: 1500;
}

@media (prefers-color-scheme: dark) { 
  #toolbar { background: rgba(13,16,22,0.95); } 
}

#toolbar.collapsed {
  min-height: auto;
}

#toolbar:not(.collapsed) {
  min-height: var(--toolbar-height);
}

.toolbar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}

.toolbar-row { 
  display: flex; 
  align-items: flex-start; 
  justify-content: space-between; 
  flex-wrap: wrap; 
  gap: 12px;
  transition: all 0.3s ease;
}

#toolbar.collapsed .toolbar-row:not(.toolbar-header) {
  opacity: 0;
  max-height: 0;
  overflow: hidden;
  margin: 0;
  padding: 0;
}

.legend { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }

.legend-title { font-weight: 600; color: var(--muted); margin-right: 6px; }

.legend-item {
  display: inline-flex; align-items: center; gap: 8px; padding: 4px 10px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 999px; box-shadow: var(--shadow); user-select: none; color: var(--text); font-size: 12px;
}

.color-box { width: 12px; height: 12px; border-radius: 3px; border: 1px solid var(--border); }

.controls { display: inline-flex; gap: 8px; align-items: center; }

.filter-controls { 
  display: flex; 
  flex-direction: column;
  gap: 12px; 
  align-items: flex-start; 
  flex: 1;
}

.filter-row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
  width: 100%;
}

.btn {
  padding: 6px 10px; font-size: 12px; border-radius: 8px;
  background: var(--surface); border: 1px solid var(--border); color: var(--text); cursor: pointer;
  transition: all 0.2s ease;
}

.btn:hover { background: var(--accent-weak); }

.btn[aria-pressed="true"] { background: var(--accent); color: white; border-color: var(--accent); }

.toggle-btn {
  padding: 4px 8px;
  font-size: 14px;
  background: transparent;
  border: none;
  color: var(--muted);
  cursor: pointer;
  border-radius: 4px;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 4px;
}

.toggle-btn:hover {
  background: var(--accent-weak);
  color: var(--accent);
}

.input {
  height: 30px; padding: 0 10px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); font-size: 12px; outline: none;
  transition: border-color 0.2s ease;
}

.input:focus { border-color: var(--accent); }

.select {
  height: 32px; padding: 0 10px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); font-size: 12px; outline: none;
  cursor: pointer; min-width: 120px;
}

.select.placeholder-type {
  background-color: #e3f2fd;
  border-color: #1976d2;
  color: #1976d2;
}

.select.placeholder-prop {
  background-color: #e8f5e9;
  border-color: #388e3c;
  color: #388e3c;
}

#property-filter option:hover {
  background-color: #388e3c;
  color: #ffffff;
}

.custom-select {
  position: relative;
  min-width: 180px;
}

.custom-select-toggle {
  height: 32px;
  padding: 0 28px 0 10px;
  width: 100%;
  border-radius: 8px;
  border: 1px solid #d1d5db;
  background: #ffffff;
  color: #111111;
  font-size: 12px;
  cursor: pointer;
  text-align: left;
  position: relative;
  box-shadow: 0 1px 0 rgba(255,255,255,0.5) inset, 0 1px 2px rgba(0,0,0,0.06);
}

.custom-select.is-prop.is-placeholder .custom-select-toggle {
  background-color: #e8f5e9;
  border-color: #388e3c;
  color: #388e3c;
}

.custom-select.is-type.is-placeholder .custom-select-toggle {
  background-color: #e3f2fd;
  border-color: #1976d2;
  color: #1976d2;
}

.custom-select-toggle:hover { background: #e8f0fe; }
.custom-select.open .custom-select-toggle { border-color: #60a5fa; }

.custom-select-toggle::after {
  content: '▾';
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--muted);
  pointer-events: none;
}

.custom-select-menu {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  background: #ffffff;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  box-shadow: 0 6px 18px rgba(0,0,0,0.12);
  max-height: 240px;
  overflow: auto;
  display: none;
  z-index: 2000;
  color: #111111;
  font-size: 12px;
  padding: 4px 0;
}

.custom-select.open .custom-select-menu {
  display: block;
}

.custom-select-option {
  padding: 2px 10px;
  cursor: pointer;
  display: flex;
  align-items: center;
  min-height: 22px;
  line-height: 16px;
  color: #111111;
  font-size: inherit;
  white-space: nowrap;
}

.custom-select-option.is-selected {
  background-color: #2563eb;
  color: #ffffff;
}

.custom-select-option:hover { background-color: #e8f0fe; }
.custom-select.is-type .custom-select-option:hover { background-color: #2563eb; color: #ffffff; }
.custom-select.is-prop .custom-select-option:hover { background-color: #388e3c; color: #ffffff; }

.custom-select-option.is-placeholder {
  color: #6b7280;
  cursor: default;
  pointer-events: none;
}

.custom-select-menu::-webkit-scrollbar { width: 10px; }
.custom-select-menu::-webkit-scrollbar-track { background: #f3f4f6; border-radius: 8px; }
.custom-select-menu::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 8px; }
.custom-select-menu::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

.filter-group {
  display: flex; gap: 6px; align-items: center;
  padding: 6px 10px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; box-shadow: var(--shadow);
}

.filter-label {
  font-size: 11px; font-weight: 600; color: var(--muted);
  white-space: nowrap;
}

.checkbox-group {
  display: flex; gap: 6px; align-items: center;
}

.checkbox {
  appearance: none;
  width: 16px; height: 16px;
  border: 2px solid var(--border);
  border-radius: 3px;
  background: var(--surface);
  cursor: pointer;
  position: relative;
  transition: all 0.2s ease;
}

.checkbox:checked {
  background: var(--accent);
  border-color: var(--accent);
}

.checkbox:checked::after {
  content: '✓';
  position: absolute;
  top: -1px;
  left: 2px;
  color: white;
  font-size: 12px;
  font-weight: bold;
}

.filter-tags-container {
  display: flex;
  flex-direction: column;
  gap: 6px;
  width: 100%;
}

.filter-tags-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  min-height: 22px;
}

.filter-tags-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  min-width: 60px;
  flex-shrink: 0;
}

.filter-tags-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  flex: 1;
}

.filter-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 6px;
  background: var(--accent-weak);
  border: 1px solid var(--accent);
  border-radius: 16px;
  font-size: 11px;
  font-weight: 500;
  color: var(--accent);
  transition: all 0.2s ease;
  user-select: none;
}

.filter-tag:hover {
  background: var(--accent);
  color: white;
}

.filter-tag-remove {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border: none;
  background: rgba(0,0,0,0.1);
  border-radius: 50%;
  cursor: pointer;
  font-size: 12px;
  line-height: 1;
  color: inherit;
  transition: all 0.2s ease;
  padding: 0;
}

.filter-tag-remove:hover {
  background: rgba(255,255,255,0.3);
  transform: scale(1.1);
}

.filter-tag.type-tag {
  background: #e3f2fd;
  border-color: #1976d2;
  color: #1976d2;
}

.filter-tag.type-tag:hover {
  background: #1976d2;
  color: white;
}

.filter-tag.property-tag {
  background: #e8f5e8;
  border-color: #388e3c;
  color: #388e3c;
}

.filter-tag.property-tag:hover {
  background: #388e3c;
  color: white;
}

.stats-controls-group {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-shrink: 0;
}

.stats-controls-group .btn {
  flex-shrink: 0;
  white-space: nowrap;
}

.stats {
  font-size: 12px; color: #ffffff;
  padding: 4px 8px; background: var(--accent-weak);
  border-radius: 6px; border: 1px solid var(--border);
}

.table-wrap {
  flex: 1;
  min-height: 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
  position: relative;
  z-index: 1;
}

.table-scroller {
  width: 100%;
  height: 100%;
  overflow: auto;
  position: relative;
}

table {
  border-collapse: separate; 
  border-spacing: 0;
  width: 100%; 
  min-width: 1200px; 
  table-layout: fixed;
  font-size: 12px;
  box-sizing: border-box;
}

thead th {
  position: sticky; 
  top: 0; 
  z-index: 10;
  background: var(--surface);
  border-bottom: 2px solid var(--border);
  border-right: 1px solid #ccc;
  color: var(--muted); 
  font-weight: 700;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  text-align: center;
}

th, td {
  border-bottom: 1px solid var(--border);
  border-right: 1px solid #ccc;
  padding: 8px 10px; 
  vertical-align: top; 
  text-align: left;
  overflow-wrap: break-word;
  box-sizing: border-box;
}

th.rownum, td.rownum { 
  position: sticky; 
  left: 0; 
  z-index: 15;
  width: 50px; 
  min-width: 50px; 
  max-width: 50px; 
  text-align: center; 
  font-weight: 700; 
  background-clip: padding-box; 
}

th.type, td.type { 
  position: sticky; 
  left: 50px;
  z-index: 15;
  width: 130px; 
  min-width: 130px; 
  max-width: 130px; 
  background-clip: padding-box; 
}

th.objname, td.objname { 
  position: sticky; 
  left: 180px;
  z-index: 15;
  width: 250px; 
  min-width: 250px; 
  max-width: 250px; 
  background-clip: padding-box; 
}

th.property, td.property { 
  position: sticky; 
  left: 430px;
  z-index: 15;
  width: 83px; 
  min-width: 83px; 
  max-width: 83px; 
  background-clip: padding-box; 
}

thead th.rownum, thead th.type, thead th.objname, thead th.property {
  z-index: 20;
}

th.rownum {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
  color: white !important;
}

th.type {
  background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%) !important;
  color: white !important;
}

th.objname {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%) !important;
  color: white !important;
}

th.property {
  background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%) !important;
  color: white !important;
}

@media (prefers-color-scheme: dark) {
  th.rownum { background: linear-gradient(135deg, #434190 0%, #5a4570 100%) !important; }
  th.type { background: linear-gradient(135deg, #c7569e 0%, #c7415a 100%) !important; }
  th.objname { background: linear-gradient(135deg, #3a8bcc 0%, #00b8cc 100%) !important; }
  th.property { background: linear-gradient(135deg, #36b567 0%, #2cc7ab 100%) !important; }
}

td.type, td.objname, td.property { color: #111 !important; }

td.vdom-column, td.vdom-column span { color: #111 !important; }

tr.row-group[data-fw-type^="config firewall"] td.type:not([class*="missing"]),
tr.row-group[data-fw-type^="config firewall"] td.objname:not([class*="missing"]),
tr.row-group[data-fw-type^="config firewall"] td.property:not([class*="missing"]),
tr.row-group[data-fw-type^="config firewall"] td.vdom-column:not(.missing-object):not(.missing-value) {
  background: #f8fafc;
}

tr.row-group[data-fw-type="config firewall address"] td.type,
tr.row-group[data-fw-type="config firewall address"] td.objname,
tr.row-group[data-fw-type="config firewall address"] td.property,
tr.row-group[data-fw-type="config firewall address"] td.vdom-column:not(.missing-object):not(.missing-value) {
    background: #e0f2fe !important;
}

tr.row-group[data-fw-type="config firewall addrgrp"] td.type,
tr.row-group[data-fw-type="config firewall addrgrp"] td.objname,
tr.row-group[data-fw-type="config firewall addrgrp"] td.property,
tr.row-group[data-fw-type="config firewall addrgrp"] td.vdom-column:not(.missing-object):not(.missing-value) {
    background: #fff3e0 !important;
}

tr.row-group[data-fw-type="config firewall service custom"] td.type,
tr.row-group[data-fw-type="config firewall service custom"] td.objname,
tr.row-group[data-fw-type="config firewall service custom"] td.property,
tr.row-group[data-fw-type="config firewall service custom"] td.vdom-column:not(.missing-object):not(.missing-value) {
    background: #e8f5e8 !important;
}

tr.row-group[data-fw-type="config firewall service group"] td.type,
tr.row-group[data-fw-type="config firewall service group"] td.objname,
tr.row-group[data-fw-type="config firewall service group"] td.property,
tr.row-group[data-fw-type="config firewall service group"] td.vdom-column:not(.missing-object):not(.missing-value) {
  background: #f3e5f5 !important;
}

tr.group-odd  td.rownum { background: #d1d9e6; color: #111; }
tr.group-even td.rownum { background: #c5d4ff; color: #111; }

th.vdom-column, td.vdom-column { width: 160px; min-width: 80px; }

.missing-object { background: #e5e5e5; color: #111 !important; }
.missing-value  { background: #fff4db; color: #111 !important; }

.hover-item > span {
  transition: background-color .15s ease, box-shadow .15s ease;
  border-radius: 6px; box-shadow: inset 0 0 0 1px rgba(0,0,0,0.05);
  color: #111 !important;
}

.hover-item.is-hovered > span {
  background: linear-gradient(0deg, rgba(59,130,246,0.16), rgba(59,130,246,0.16)) !important;
  box-shadow: 0 0 0 2px var(--accent);
}

.tooltip {
  position: fixed;
  z-index: 10000;
  pointer-events: none;
  background: var(--surface);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 8px 10px;
  box-shadow: var(--shadow);
  font-size: 11px;
  display: none;
  max-width: 320px;
}

.tooltip .tooltip-title {
  font-weight: 700;
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 6px;
}

.tooltip .chip-list { display: flex; flex-wrap: wrap; gap: 6px; }

.tooltip .vdom-chip {
  display: inline-flex;
  align-items: center;
  padding: 0px 8px;
  border-radius: 999px;
  border: 1px solid rgba(0,0,0,0.1);
}

.loading {
  opacity: 0.6;
  pointer-events: none;
}

.loading::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 24px;
  height: 24px;
  margin: -12px 0 0 -12px;
  border: 2px solid var(--border);
  border-top: 2px solid var(--accent);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
</head>
<body>
<a href="https://github.com/smilestory-net" target="_blank" class="credit" rel="noopener noreferrer">Created by github.com/smilestory-net with AI-powered</a>

<div class="container">
  <h3>FGT config files VDOM object comparison</h3>

  <div id="toolbar" class="collapsed">
    <div class="toolbar-header">
      <div class="legend" id="legend-container">
        <span class="legend-title">Files</span>'''

    # Legend items
    for fname in file_names:
        color = file_name_to_color[fname]
        html_content += f'<span class="legend-item"><span class="color-box" style="background-color:{color};"></span><span>{html.escape(fname)}</span></span>'

    html_content += '''
      </div>
      <div class="controls">
        <button id="toggle-filters" class="toggle-btn" type="button">
          <span id="toggle-icon">▶</span> Filters
        </button>
        <button id="toggle-hover" class="btn" aria-pressed="true" type="button">Hover: ON</button>
        <button id="toggle-tooltip" class="btn" aria-pressed="true" type="button">Tooltip: ON</button>
      </div>
    </div>

    <div class="toolbar-row">
      <div class="filter-controls">
        <div class="filter-row">
            <div class="filter-group">
            <span class="filter-label">Type:</span>
            <div id="type-filter-wrapper" class="custom-select is-type is-placeholder" data-placeholder="Select type...">
              <button type="button" class="custom-select-toggle" id="type-toggle">Select type...</button>
              <div class="custom-select-menu" id="type-menu">
'''

    # Type options (custom menu)
    for fw_type in sorted(all_types):
        display_name = fw_type.replace("config firewall ", "").title()
        safe_val = html.escape(fw_type)
        safe_text = html.escape(display_name)
        html_content += f'<div class="custom-select-option" data-value="{safe_val}">{safe_text}</div>'

    html_content += '''
              </div>
            </div>
          </div>
          
          <div class="filter-group">
            <span class="filter-label">Property:</span>
            <div id="property-filter-wrapper" class="custom-select is-prop is-placeholder" data-placeholder="Select property...">
              <button type="button" class="custom-select-toggle" id="property-toggle">Select property...</button>
              <div class="custom-select-menu" id="property-menu">
'''

    # Property options (custom menu)
    for prop in sorted(all_properties):
        safe_prop = html.escape(prop)
        html_content += f'<div class="custom-select-option" data-value="{safe_prop}">{safe_prop}</div>'

    html_content += '''
              </div>
            </div>
          </div>
          
          <div class="filter-group">
            <span class="filter-label">Search:</span>
            <input id="filter-input" class="input" type="search" placeholder="Search object name..." style="min-width: 200px;" />
          </div>
          
          <div class="filter-group">
            <span class="filter-label">Contains Value:</span>
            <input id="value-filter" class="input" type="search" placeholder="Search for specific value..." style="min-width: 150px;" />
          </div>
          
          <div class="filter-group">
            <button id="invert-toggle" class="btn" aria-pressed="false" type="button">Invert Type/Property: OFF</button>
          </div>
        </div>

        <div class="filter-tags-container">
          <div class="filter-tags-row">
            <span class="filter-tags-label">Type/Property Filters:</span>
            <div class="filter-tags-list" id="combined-tags"></div>
          </div>
        </div>
      </div>

      <div class="stats-controls-group">
        <button id="reset-filters" class="btn" type="button">Reset Filters</button>
        <div class="stats" id="filter-stats">
            Total <span id="total-rows">''' + str(initial_total_rows) + '''</span> rows, <span id="visible-rows">''' + str(initial_total_rows) + '''</span> visible
        </div>
      </div>      
    </div>
  </div>

  <div class="table-wrap" id="table-wrap">
    <div class="table-scroller">
      <table>
        <thead>
          <tr>
            <th class="rownum">No.</th>
            <th class="type">Type</th>
            <th class="objname">Object Name</th>
            <th class="property">Property</th>
'''

    # Header: VDOM columns
    for label in col_labels:
        bgcolor = label_colors[label]
        def _gc(bg):
            bg = bg.lstrip('#')
            r, g, b = int(bg[0:2], 16), int(bg[2:4], 16), int(bg[4:6], 16)
            return "#000000" if (r * 299 + g * 587 + b * 114) / 1000 > 150 else "#ffffff"
        textcolor = _gc(bgcolor)
        vdom_name = label.split("\n")[1].strip("[]")
        html_content += (
            f'<th class="vdom-column" '
            f'style="background:{bgcolor};color:{textcolor}">'
            f'{html.escape(vdom_name)}</th>'
        )
    html_content += '''
          </tr>
        </thead>
        <tbody id="table-body">
''' + initial_table_content + '''
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
// Global data storage
const originalData = ''' + json.dumps({
        'all_objects': {f"{fw_type}____{obj_name}": label_props for (fw_type, obj_name), label_props in all_objects.items()},
        'col_labels': col_labels,
        'diffs': {f"{fw_type}____{obj_name}": prop_diffs for (fw_type, obj_name), prop_diffs in diffs.items()},
        'label_colors': label_colors
    }) + r''';
    
document.addEventListener("DOMContentLoaded", function() {
  let hoverEnabled = true;
  let tooltipEnabled = true;
  let filtersCollapsed = true;
  
  const tooltip = document.createElement('div');
  tooltip.id = 'hover-tooltip';
  tooltip.className = 'tooltip';
  document.body.appendChild(tooltip);
  
  const filterState = {
    types: new Set(),
    properties: new Set(),
    search: '',
    value: '',
    invert: false
  };

  const tableWrap = document.getElementById("table-wrap");
  const tableBody = document.getElementById("table-body");
  const scroller = document.querySelector(".table-scroller");
  const table = scroller?.querySelector("table");
  const toolbar = document.getElementById("toolbar");
  const toggleBtn = document.getElementById("toggle-hover");
  const toggleTooltipBtn = document.getElementById("toggle-tooltip");
  const resetBtn = document.getElementById("reset-filters");
  const toggleFiltersBtn = document.getElementById("toggle-filters");
  const toggleIcon = document.getElementById("toggle-icon");
  
  let isLeftShiftPressed = false;
  document.addEventListener('keydown', (e) => {
    if (e.code === 'ShiftLeft') isLeftShiftPressed = true;
  });
  document.addEventListener('keyup', (e) => {
    if (e.code === 'ShiftLeft') isLeftShiftPressed = false;
  });
  
  const typeFilterWrapper = document.getElementById("type-filter-wrapper");
  const typeToggle = document.getElementById("type-toggle");
  const typeMenu = document.getElementById("type-menu");
  const propertyFilterWrapper = document.getElementById("property-filter-wrapper");
  const propertyToggle = document.getElementById("property-toggle");
  const propertyMenu = document.getElementById("property-menu");
  const filterInput = document.getElementById("filter-input");
  const valueFilter = document.getElementById("value-filter");
  const invertToggle = document.getElementById("invert-toggle");
  
  const combinedTagsContainer = document.getElementById("combined-tags");
  
  const totalRowsSpan = document.getElementById("total-rows");
  const visibleRowsSpan = document.getElementById("visible-rows");
  
  if (typeof window.__fixedTotal !== 'number') { 
    const initFixed = tableBody.querySelectorAll('td.rownum').length;
    window.__fixedTotal = initFixed;
    totalRowsSpan.textContent = String(window.__fixedTotal);
  }

  function createFilterTag(text, type, value) {
    const tag = document.createElement('div');
    tag.className = `filter-tag ${type}-tag`;
    tag.innerHTML = `
      <span>${text}</span>
      <button class="filter-tag-remove" data-type="${type}" data-value="${value}">×</button>
    `;
    return tag;
  }
  
  function updateFilterTags() {
    combinedTagsContainer.innerHTML = '';
    filterState.types.forEach(type => {
      const displayText = type.replace("config firewall ", "").replace(/\b\w/g, l => l.toUpperCase());
      const tag = createFilterTag(displayText, 'type', type);
      combinedTagsContainer.appendChild(tag);
    });
    filterState.properties.forEach(prop => {
      const tag = createFilterTag(prop, 'property', prop);
      combinedTagsContainer.appendChild(tag);
    });
  }
  
  function handleTagRemove(e) {
    const target = e.target.closest('.filter-tag-remove');
    if (!target) return;
    
    const type = target.dataset.type;
    const value = target.dataset.value;
    
    if (type === 'type') {
      filterState.types.delete(value);
    } else if (type === 'property') {
      filterState.properties.delete(value);
    }
    
    updateFilterTags();
    applyFilters();
  }
  
  combinedTagsContainer.addEventListener('click', handleTagRemove);

  function updateStats() {
    const visibleRows = Array.from(tableBody.querySelectorAll('tr')).filter(tr => 
      tr.querySelector('td.rownum') && tr.offsetParent !== null
    ).length;
    visibleRowsSpan.textContent = visibleRows.toString();
  }

  function getContrastColor(hex) {
    if (!hex) return '#000000';
    const h = hex.replace('#','');
    const r = parseInt(h.substring(0,2), 16);
    const g = parseInt(h.substring(2,4), 16);
    const b = parseInt(h.substring(4,6), 16);
    const brightness = (r * 299 + g * 587 + b * 114) / 1000;
    return brightness > 150 ? '#000000' : '#ffffff';
  }

  function showTooltip(html, pageX, pageY) {
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
    positionTooltip(pageX, pageY);
  }

  function hideTooltip() {
    tooltip.style.display = 'none';
  }

  function positionTooltip(pageX, pageY) {
    const offset = 14;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    tooltip.style.left = Math.min(pageX + offset, vw - tooltip.offsetWidth - 8) + 'px';
    tooltip.style.top  = Math.min(pageY + offset, vh - tooltip.offsetHeight - 8) + 'px';
  }

  function highlightDifferencesAcrossVdoms(values) {
    const vdomItems = {};
    const itemCount = {};
    
    for (const [vdom, val] of Object.entries(values)) {
      if (!val || val === "") {
        vdomItems[vdom] = [];
      } else {
        const items = val.includes('"') ? 
          (val.match(/"([^"]*)"/g) || []).map(item => item.slice(1, -1)) : 
          [val];
        vdomItems[vdom] = items;
        for (const item of items) {
          itemCount[item] = (itemCount[item] || 0) + 1;
        }
      }
    }

    const DUPLICATE_COLORS = [
      "#ffff99", "#ccffcc", "#99ccff", "#ffcc99", "#ff99cc", "#ccccff", 
      "#ffd699", "#c2f0c2", "#b3e6ff", "#ffb3b3", "#d9b3ff", "#ffffb3",
      "#66ff66", "#66ccff", "#ff6666", "#ffcc00", "#9966ff", "#66ffff", 
      "#ff9966", "#66ffcc", "#ff66cc", "#99ff66", "#3399ff", "#ffcc66",
      "#cc99ff", "#99ffff", "#ff9999", "#ccff66", "#66b3ff", "#ff66ff", 
      "#aaffaa", "#ffb366", "#c299ff", "#99ffcc", "#ff6699", "#b3ff66"
    ];
    
    const colorMap = {};
    let colorIndex = 0;
    for (const item of Object.keys(itemCount).sort()) {
      if (itemCount[item] >= 2) {
        colorMap[item] = DUPLICATE_COLORS[colorIndex % DUPLICATE_COLORS.length];
        colorIndex++;
      }
    }

    const highlightedValues = {};
    const duplicateItems = new Set(
      Object.keys(itemCount).filter(item => itemCount[item] >= 2)
    );

    for (const [vdom, items] of Object.entries(vdomItems)) {
      const highlightedParts = [];
      for (const item of items) {
        const color = colorMap[item] || "#ff6666";
        highlightedParts.push(`<span style="background-color:${color}">"${item}"</span>`);
      }
      highlightedValues[vdom] = highlightedParts.length ? highlightedParts.join("<br>") : "";
    }

    return { highlightedValues, duplicateItems };
  }

  function wrapHoverSpansWithColor(text, groupId, duplicateItems) {
    const spanPattern = /(<span style="background-color:[^"]+">"([^"]*)"<\/span>)/g;
    let result = '';
    let lastIndex = 0;
    let match;

    while ((match = spanPattern.exec(text)) !== null) {
      result += text.slice(lastIndex, match.index);
      const [fullSpan, , val] = match;
      
      if (duplicateItems.has(val)) {
        result += `<span class="hover-item" data-val="${val.replace(/"/g, '&quot;')}" data-row="${groupId}">${fullSpan}</span>`;
      } else {
        result += fullSpan;
      }
      lastIndex = match.index + match[0].length;
    }
    result += text.slice(lastIndex);
    return result;
  }

  // Define property sort order (same as Python code)
  const PROPERTY_ORDER = [
    'type', 'subnet', 'start-ip', 'end-ip', 'fqdn', 'associated-interface',
    'protocol', 'tcp-portrange', 'udp-portrange', 'icmptype', 'icmpcode', 
    'sctp-portrange', 'protocol-number', 'iprange', 'category',
    'member', 'exclude-member', 'visibility',
    'comment', 'color', 'fabric-object', 'allow-routing', 'interface'
  ];
  
  function getPropertySortKey(prop) {
    const index = PROPERTY_ORDER.indexOf(prop);
    return index >= 0 ? [0, index, prop] : [1, 0, prop];
  }

  function regenerateTable(filteredDiffs) {
    tableWrap.classList.add("loading");
    
    setTimeout(() => {
      let tableContent = "";
      let rowNum = 1;

      for (const [key, propDiffs] of Object.entries(filteredDiffs).sort()) {
        const [fwType, objName] = key.split('____');
        
        // Sort properties consistently
        const sortedProps = Object.entries(propDiffs).sort(([propA], [propB]) => {
          const [orderA, indexA, nameA] = getPropertySortKey(propA);
          const [orderB, indexB, nameB] = getPropertySortKey(propB);
          
          if (orderA !== orderB) return orderA - orderB;
          if (indexA !== indexB) return indexA - indexB;
          return nameA.localeCompare(nameB);
        });
        
        const rowspan = sortedProps.length;
        const groupClass = (rowNum % 2 === 0) ? "group-even" : "group-odd";

        for (let idx2 = 0; idx2 < sortedProps.length; idx2++) {
          const [prop, values] = sortedProps[idx2];

          tableContent += `<tr class="row-group ${groupClass}" data-group="${rowNum}" data-fw-type="${fwType.replace(/"/g, '&quot;')}">`;

          if (idx2 === 0) {
            tableContent += `<td class="rownum" rowspan="${rowspan}">${rowNum}</td>`;
            tableContent += `<td class="type" rowspan="${rowspan}">${fwType.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>`;
            tableContent += `<td class="objname" rowspan="${rowspan}">${objName.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>`;
          }
          tableContent += `<td class="property">${prop.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>`;

          const { highlightedValues, duplicateItems } = highlightDifferencesAcrossVdoms(values);

          for (const label of originalData.col_labels) {
            const val = values[label] || "";
            const objKey = `${fwType}____${objName}`;
            const objProps = originalData.all_objects[objKey] && originalData.all_objects[objKey][label];
            
            let cellText, cellClass;
            if (!objProps) {
              cellText = "Object missing";
              cellClass = "missing-object";
            } else if (val === "") {
              cellText = "No property value";
              cellClass = "missing-value";
            } else {
              const coloredVal = highlightedValues[label] || "";
              cellText = wrapHoverSpansWithColor(coloredVal, rowNum, duplicateItems);
              cellClass = "";
            }
            tableContent += `<td class="vdom-column ${cellClass}">${cellText}</td>`;
          }
          tableContent += "</tr>";
        }
        rowNum++;
      }

      tableBody.innerHTML = tableContent;

      if (typeof window.__fixedTotal === 'number') {
        totalRowsSpan.textContent = String(window.__fixedTotal);
      } else {
        const fixed = tableBody.querySelectorAll('td.rownum').length;
        window.__fixedTotal = fixed;
        totalRowsSpan.textContent = String(window.__fixedTotal);
      }

      updateStats();
      tableWrap.classList.remove("loading");
    }, 50);
  }

  function applyFilters() {
    const filters = {
      types: filterState.types,
      properties: filterState.properties,
      search: filterState.search.toLowerCase(),
      value: filterState.value.toLowerCase(),
      invert: filterState.invert
    };

    const hasTypeOrProp = (filters.types.size > 0) || (filters.properties.size > 0);
    const hasTypePropOrValue = hasTypeOrProp || !!filters.value;

    const filteredDiffs = {};

    for (const [key, propDiffs] of Object.entries(originalData.diffs)) {
      const parts = key.split("____");
      const fwType = String(parts[0] || "");
      const objName = String(parts[1] || "");

      const nameCondition = !filters.search || objName.toLowerCase().includes(filters.search);
      const typeCondition = (filters.types.size === 0) ||
        Array.from(filters.types).some(t => fwType.toLowerCase().includes(t.toLowerCase()));

      let matchedProps = {};

      for (const [prop, values] of Object.entries(propDiffs)) {
        const propCondition = (filters.properties.size === 0) ||
          Array.from(filters.properties).some(p => String(prop).toLowerCase().includes(p.toLowerCase()));

        const valueCondition = !filters.value ||
          Object.values(values).some(v => String(v == null ? "" : v).toLowerCase().includes(filters.value));

        let isMatch = typeCondition && nameCondition && propCondition && valueCondition;

        if (filters.invert && hasTypeOrProp) {
          const invertedTypeOrProp = (!typeCondition) || (!propCondition);
          isMatch = invertedTypeOrProp && nameCondition && valueCondition;
        } else if (!hasTypePropOrValue) {
          isMatch = nameCondition;
        }

        if (isMatch) {
          matchedProps[prop] = values;
        }
      }

      if (Object.keys(matchedProps).length > 0) {
        filteredDiffs[key] = matchedProps;
      }
    }

    regenerateTable(filteredDiffs);
  }

  function resetFilters() {
    filterState.types.clear();
    filterState.properties.clear();
    filterState.search = '';
    filterState.value = '';
    filterState.invert = false;

    typeFilterWrapper?.classList.add('is-placeholder');
    propertyFilterWrapper?.classList.add('is-placeholder');
    
    const typePh = typeFilterWrapper?.dataset.placeholder || 'Select type...';
    const propPh = propertyFilterWrapper?.dataset.placeholder || 'Select property...';
    const typeBtn = typeFilterWrapper?.querySelector('.custom-select-toggle');
    const propBtn = propertyFilterWrapper?.querySelector('.custom-select-toggle');
    if (typeBtn) typeBtn.textContent = typePh; 
    if (propBtn) propBtn.textContent = propPh;

    if (filterInput) filterInput.value = '';
    if (valueFilter) valueFilter.value = '';

    if (invertToggle) {
      invertToggle.setAttribute('aria-pressed', 'false');
      invertToggle.textContent = 'Invert Type/Property: OFF';
    }

    updateFilterTags();
    regenerateTable(originalData.diffs);
  }

  toggleFiltersBtn?.addEventListener("click", () => {
    filtersCollapsed = !filtersCollapsed;
    toolbar.classList.toggle("collapsed", filtersCollapsed);
    toggleIcon.textContent = filtersCollapsed ? "▶" : "▼";
  });

  toggleBtn?.addEventListener("click", () => {
    hoverEnabled = !hoverEnabled;
    toggleBtn.setAttribute("aria-pressed", hoverEnabled ? "true" : "false");
    toggleBtn.textContent = "Hover: " + (hoverEnabled ? "ON" : "OFF");
    table?.querySelectorAll(".hover-item.is-hovered").forEach(el => el.classList.remove("is-hovered"));
    if (!hoverEnabled) hideTooltip();
  });

  toggleTooltipBtn?.addEventListener("click", () => {
    tooltipEnabled = !tooltipEnabled;
    toggleTooltipBtn.setAttribute("aria-pressed", tooltipEnabled ? "true" : "false");
    toggleTooltipBtn.textContent = "Tooltip: " + (tooltipEnabled ? "ON" : "OFF");
    if (!tooltipEnabled) hideTooltip();
  });

  function closeTypeMenu() {
    typeFilterWrapper?.classList.remove('open');
  }
  
  typeToggle?.addEventListener('click', (e) => {
    e.stopPropagation();
    typeFilterWrapper?.classList.toggle('open');
  });
  
  typeMenu?.addEventListener('click', (e) => {
    const option = e.target.closest('.custom-select-option');
    if (!option) return;
    const value = option.getAttribute('data-value') || '';
    if (value && !filterState.types.has(value)) {
      filterState.types.add(value);
      updateFilterTags();
      applyFilters();
    }
    closeTypeMenu();
  });

  function closePropertyMenu() {
    propertyFilterWrapper?.classList.remove('open');
  }

  propertyToggle?.addEventListener('click', (e) => {
    e.stopPropagation();
    propertyFilterWrapper?.classList.toggle('open');
  });

  propertyMenu?.addEventListener('click', (e) => {
    const option = e.target.closest('.custom-select-option');
    if (!option) return;
    const value = option.getAttribute('data-value') || '';
    if (value && !filterState.properties.has(value)) {
      filterState.properties.add(value);
      updateFilterTags();
      applyFilters();
    }
    closePropertyMenu();
  });

  document.addEventListener('click', (e) => {
    if (!propertyFilterWrapper?.contains(e.target)) {
      closePropertyMenu();
    }
    if (!typeFilterWrapper?.contains(e.target)) {
      closeTypeMenu();
    }
  });

  function attachEnterApply(el, setter) {
    if (!el) return;
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        setter(e.target.value);
        applyFilters();
      }
    });
    el.addEventListener('search', (e) => {
      setter(e.target.value);
      applyFilters();
    });
    el.addEventListener('input', (e) => {
      if (e.target.value === '') {
        setter('');
        applyFilters();
      }
    });
  }
  
  attachEnterApply(filterInput, (v) => { filterState.search = v; });
  attachEnterApply(valueFilter, (v) => { filterState.value = v; });

  invertToggle?.addEventListener('click', () => {
    filterState.invert = !filterState.invert;
    invertToggle.setAttribute('aria-pressed', filterState.invert ? 'true' : 'false');
    invertToggle.textContent = 'Invert Type/Property: ' + (filterState.invert ? 'ON' : 'OFF');
    applyFilters();
  });

  resetBtn?.addEventListener("click", resetFilters);

  scroller?.addEventListener("mouseover", (e) => {
    if (!hoverEnabled && !tooltipEnabled) return;
    const target = e.target.closest(".hover-item");
    if (!target) return;
    const val = target.getAttribute("data-val");
    const row = target.getAttribute("data-row");
    if (!val || !row) return;
    if (hoverEnabled) {
      table.querySelectorAll('.hover-item[data-val="' + CSS.escape(val) + '"][data-row="' + CSS.escape(row) + '"]')
           .forEach(el => el.classList.add("is-hovered"));
    }

    if (!tooltipEnabled) return;

    try {
      const tr = target.closest('tr');
      if (!tr) return;
      const groupId = tr.getAttribute('data-group');
      const typeCell = tableBody.querySelector('tr[data-group="' + CSS.escape(groupId) + '"] td.type');
      const objCell = tableBody.querySelector('tr[data-group="' + CSS.escape(groupId) + '"] td.objname');
      const propCell = tr.querySelector('td.property');
      if (!typeCell || !objCell || !propCell) return;
      const fwType = typeCell.textContent.trim();
      const objName = objCell.textContent.trim();
      const propName = propCell.textContent.trim();
      const key = fwType + '____' + objName;
      const propDiffs = originalData.diffs[key];
      if (!propDiffs) return;
      const values = propDiffs[propName];
      if (!values) return;

      const labelsContaining = [];
      for (const label of originalData.col_labels) {
        const v = values[label] || '';
        let items;
        if (typeof v === 'string' && v.includes('"')) {
          const m = v.match(/"([^"]*)"/g) || [];
          items = m.map(s => s.slice(1, -1));
        } else if (v == null || v === '') {
          items = [];
        } else {
          items = [String(v)];
        }
        if (items.includes(val)) {
          labelsContaining.push(label);
        }
      }

      if (labelsContaining.length > 0) {
        let html = '<div class="tooltip-title">VDOMs containing duplicate value</div><div class="chip-list">';
        for (const label of labelsContaining) {
          const bg = originalData.label_colors?.[label] || '#e5e7eb';
          const textColor = getContrastColor(bg);
          const vdomName = (label.split('\n')[1] || '').replace('[','').replace(']','');
          html += '<span class="vdom-chip" style="background:' + bg + ';color:' + textColor + ';border-color:' + bg + '">' +
                  vdomName.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span>';
        }
        html += '</div>';
        showTooltip(html, e.pageX, e.pageY);
      } else {
        hideTooltip();
      }
    } catch (_) {
      // Ignore safely
    }
  });

  scroller?.addEventListener("mouseout", (e) => {
    const target = e.target.closest(".hover-item");
    if (!target) return;
    const val = target.getAttribute("data-val");
    const row = target.getAttribute("data-row");
    if (!val || !row) return;
    if (hoverEnabled) {
      table.querySelectorAll('.hover-item[data-val="' + CSS.escape(val) + '"][data-row="' + CSS.escape(row) + '"]')
           .forEach(el => el.classList.remove("is-hovered"));
    }
    if (tooltipEnabled) hideTooltip();
  });

  scroller?.addEventListener('mousemove', (e) => {
    if (tooltipEnabled && tooltip.style.display === 'block') {
      positionTooltip(e.pageX, e.pageY);
    }
  });

  function addColumnResizers() {
    if (!table) return;
    const ths = table.querySelectorAll("thead th");
    ths.forEach((th, i) => {
      if (th.classList.contains("rownum") || th.classList.contains("type") ||
          th.classList.contains("objname") || th.classList.contains("property")) {
        return;
      }
      th.classList.add("resizable");
      const handle = document.createElement("span");
      handle.className = "resize-handle";
      th.appendChild(handle);

      let startX = 0, startW = 0, colIndex = i + 1;
      function onMouseMove(e) {
        const dx = e.clientX - startX;
        const newW = Math.max(50, startW + dx);
        th.style.width = newW + "px";
        table.querySelectorAll('tr > *:nth-child(' + colIndex + ')').forEach(cell => {
          cell.style.width = newW + "px";
        });
      }
      function onMouseUp() {
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
      }
      handle.addEventListener("mousedown", (e) => {
        e.preventDefault();
        startX = e.clientX;
        startW = th.getBoundingClientRect().width;
        document.body.style.userSelect = "none";
        document.addEventListener("mousemove", onMouseMove);
        document.addEventListener("mouseup", onMouseUp);
      });
    });
  }

  updateStats();
  addColumnResizers();

  function updateSelectPlaceholderStyles() {
    if (typeFilterWrapper) {
      typeFilterWrapper.classList.add('is-placeholder');
    }
    if (propertyFilterWrapper) {
      propertyFilterWrapper.classList.add('is-placeholder');
    }
  }
  updateSelectPlaceholderStyles();
  
  scroller?.addEventListener('wheel', (e) => {
    if (!isLeftShiftPressed) return;
    if (!scroller) return;
    e.preventDefault();
    const delta = Math.abs(e.deltaY) > Math.abs(e.deltaX) ? e.deltaY : e.deltaX;
    scroller.scrollLeft += delta;
  }, { passive: false });
});
</script>
</body>
</html>
'''

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Enhanced HTML report with consistent property order generated: {output_file}")
    webbrowser.open(output_file)

# =========================
# Main
# =========================
if __name__ == "__main__":
    print("=== FortiGate Config Files VDOM Object Comparison ===")
    print("File selection window will open...")

    try:
        file_paths = select_files()
        if not file_paths:
            print("No files were selected.")
            input("Press any key to exit...")
            exit()

        print(f"Number of selected files: {len(file_paths)}")
        for i, path in enumerate(file_paths, 1):
            print(f"{i}. {os.path.basename(path)}")

        if len(file_paths) == 1:
            print("\nAnalyzing single file...")
            is_single, vdom_data = parse_config_file(file_paths[0])
            if is_single:
                print("Cannot compare (only a single VDOM configuration file was selected).")
                input("Press any key to exit...")
            else:
                file_vdom_map = {file_paths[0]: vdom_data}
                all_objects, col_labels, diffs = compare_objects_across_files(file_vdom_map)
                print(f"Analysis complete! {len(diffs)} differences found.")
                generate_html_report(all_objects, col_labels, diffs)
                print("HTML report has been generated and opened in your browser.")
        else:
            print(f"\nAnalyzing multiple files... ({len(file_paths)} files)")
            file_vdom_map = {}
            for path in file_paths:
                print(f"Parsing: {os.path.basename(path)}")
                _, vdom_data = parse_config_file(path)
                file_vdom_map[path] = vdom_data

            print("Comparing and analyzing...")
            all_objects, col_labels, diffs = compare_objects_across_files(file_vdom_map)
            print(f"Analysis complete! {len(diffs)} differences found.")
            generate_html_report(all_objects, col_labels, diffs)
            print("HTML report has been generated and opened in your browser.")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        input("Press any key to exit...")
