import re
import html
import tkinter as tk
from tkinter import filedialog
import webbrowser
import os

# GUI function to let the user select multiple FortiGate config files
def select_files():
    root = tk.Tk()
    root.withdraw()  # Hide the default Tkinter window
    file_paths = filedialog.askopenfilenames(
        title="Select FortiGate Config Files",
        filetypes=[("Config files", "*.conf *.txt"), ("All files", "*.*")]
    )
    return list(file_paths)

# Determine whether the config is a single VDOM (absence of "config vdom")
def is_single_vdom(config_text):
    return "config vdom" not in config_text

# Extract firewall-related objects from config blocks (address, addrgrp, etc.)
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
                if key.lower() in ["uuid", "associated-interface"]:
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

# Parse config file and extract per-VDOM firewall objects
def parse_config_file(file_path):
    with open(file_path, encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    is_single = is_single_vdom(config_text)
    vdom_data = {}

    if is_single:
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

    return is_single, vdom_data

# Color mapping per object type
OBJ_COLOR_MAP = {
    "config firewall address": "#e0f7fa",
    "config firewall addrgrp": "#fff3e0",
    "config firewall service custom": "#e8f5e9",
    "config firewall service group": "#f3e5f5"
}

# Order of object types for sorting
OBJ_TYPE_ORDER = [
    "config firewall address",
    "config firewall addrgrp",
    "config firewall service custom",
    "config firewall service group"
]

# Compare objects across multiple files and VDOMs
def compare_objects_across_files(file_vdom_map):
    all_objects = {}
    col_labels = []

    for file_path, vdoms in file_vdom_map.items():
        file_label = os.path.basename(file_path)
        for vdom in vdoms.keys():
            label = f"{file_label}\n[{vdom}]"
            col_labels.append(label)

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

    diffs = {}
    for (fw_type, obj_name), label_props in all_objects.items():
        all_props = {}
        for props in label_props.values():
            for p in props.keys():
                all_props[p] = True

        obj_diff = {}
        for prop in all_props:
            values = {}
            valid_labels = [label for label in col_labels if label in label_props]
            for label in valid_labels:
                val = label_props.get(label, {}).get(prop, "")
                if val is None:
                    val = ""
                values[label] = val

            if len(values) < 2 or len(set(values.values())) <= 1:
                continue
            obj_diff[prop] = values

        if obj_diff:
            diffs[(fw_type, obj_name)] = obj_diff

    return all_objects, col_labels, diffs

# Highlight differing values with background color
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
    for vdom, items in vdom_items.items():
        highlighted_parts = []
        for item in items:
            if item in color_map:
                highlighted_parts.append(f'<span style="background-color:{color_map[item]}">"{item}"</span>')
            else:
                highlighted_parts.append(f'<span style="background-color:#ff6666">"{item}"</span>')
        highlighted_values[vdom] = " ".join(highlighted_parts) if highlighted_parts else ""
    return highlighted_values

# Generate HTML report
def generate_html_report(all_objects, col_labels, diffs, output_file="report_fgt_duplicate_address_object.html"):
    colors = [
        "#1976D2", "#388E3C", "#FBC02D", "#F57C00",
        "#7B1FA2", "#00796B", "#C2185B", "#303F9F",
        "#FFA000", "#5D4037", "#455A64", "#D32F2F"
    ]

    file_names = []
    file_name_to_color = {}
    for label in col_labels:
        fname = label.split("\n")[0]
        if fname not in file_names:
            file_names.append(fname)
    for i, fname in enumerate(file_names):
        file_name_to_color[fname] = colors[i % len(colors)]

    label_colors = {}
    for label in col_labels:
        fname = label.split("\n")[0]
        label_colors[label] = file_name_to_color.get(fname, "#ffffff")

    def get_contrast_color(bgcolor):
        bg = bgcolor.lstrip('#')
        r, g, b = int(bg[0:2], 16), int(bg[2:4], 16), int(bg[4:6], 16)
        brightness = (r * 299 + g * 587 + b * 114) / 1000
        return "#000000" if brightness > 150 else "#ffffff"

    html_content = f"""
    <html><head><meta charset='UTF-8'>
    <style>
    body {{ font-family: Arial; margin: 0; }}
    #legend-container {{
        position: sticky;
        top: 0px;
        background: white;
        padding: 15px 5px;
        font-size: 13px;
        z-index: 1000;
        border-bottom: 1px solid #ccc;
    }}
    .legend-item {{
        display: inline-block;
        margin-right: 15px;
        font-size: 13px;
        user-select: none;
        color: black;
    }}
    .color-box {{
        width: 15px;
        height: 15px;
        display: inline-block;
        vertical-align: middle;
        margin-right: 5px;
        border: 1px solid #aaa;
    }}
    table {{
        border-collapse: collapse;
        width: 100%;
        font-size: 11px;
        margin-top: 0;
        table-layout: fixed;
    }}
    thead th {{
        position: sticky;
        top: 48px;
        z-index: 999;
        background-color: #f9f9f9;
    }}
    th, td {{
        border: 1px solid #ccc;
        padding: 5px;
        vertical-align: top;
        text-align: left;
        overflow-wrap: break-word;
    }}
    th.rownum, td.rownum {{ width: 20px; text-align: center; font-weight: bold; }}
    th.type, td.type {{ width: 80px; }}
    th.objname, td.objname {{ width: 180px; }}
    th.property, td.property {{ width: 50px; }}
    .vdom-column {{ width: 120px; }}
    th.rownum, th.type, th.objname, th.property {{
        background-color: #f0f0f0 !important;
        color: black !important;
    }}
    .missing-object {{ background-color: #eeeeee; }}
    .missing-value {{ background-color: #fff9c4; }}
    .rownum-odd {{ background: #dddddd; }}
    .rownum-even {{ background: #ffffff; }}
    </style>
    </head><body>
    <h3>FortiGate Config VDOM Object Comparison (Duplicates Colored, Unique in Red)</h3>
    <div id="legend-container"><strong>Column colors by file: </strong>
    """

    for fname in file_names:
        color = file_name_to_color[fname]
        html_content += f'<span class="legend-item"><span class="color-box" style="background-color:{color};"></span><span>{html.escape(fname)}</span></span>'
    html_content += "</div>"

    html_content += "<table><thead><tr>"
    html_content += """
    <th class="rownum">No.</th>
    <th class="type">Type</th>
    <th class="objname">Object Name</th>
    <th class="property">Property</th>
    """
    for label in col_labels:
        bgcolor = label_colors[label]
        textcolor = get_contrast_color(bgcolor)
        vdom_name = label.split("\n")[1].strip("[]")
        html_content += f'<th class="vdom-column" style="background-color:{bgcolor}; color:{textcolor}">{html.escape(vdom_name)}</th>'
    html_content += "</tr></thead><tbody>"

    row_num = 1
    for (fw_type, obj_name), prop_diffs in sorted(diffs.items(), key=lambda x: (
            OBJ_TYPE_ORDER.index(x[0][0]) if x[0][0] in OBJ_TYPE_ORDER else 999,
            x[0][1].lower()
    )):
        prop_list = list(prop_diffs.items())
        rowspan = len(prop_list)
        bg_color = OBJ_COLOR_MAP.get(fw_type, "#ffffff")
        rownum_class = "rownum-odd" if row_num % 2 == 1 else "rownum-even"

        for idx, (prop, values) in enumerate(prop_list):
            html_content += f'<tr style="background-color:{bg_color};">'
            if idx == 0:
                html_content += f'<td class="rownum {rownum_class}" rowspan="{rowspan}">{row_num}</td>'
                html_content += f'<td class="type" rowspan="{rowspan}">{html.escape(fw_type)}</td>'
                html_content += f'<td class="objname" rowspan="{rowspan}">{html.escape(obj_name)}</td>'
            html_content += f'<td class="property">{html.escape(prop)}</td>'

            highlighted_vals = highlight_differences_across_vdoms(values)
            for label in col_labels:
                obj_props = all_objects.get((fw_type, obj_name), {}).get(label, None)
                val = values.get(label, "")
                if obj_props is None:
                    cell_text = "Object Missing"
                    cell_class = "missing-object"
                elif val == "":
                    cell_text = "No Value"
                    cell_class = "missing-value"
                else:
                    cell_text = highlighted_vals[label]
                    cell_class = ""
                html_content += f'<td class="vdom-column {cell_class}">{cell_text}</td>'
            html_content += "</tr>"
        row_num += 1

    html_content += "</tbody></table></body></html>"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report generated: {output_file}")
    webbrowser.open(output_file)

# Main function
if __name__ == "__main__":
    file_paths = select_files()

    if not file_paths:
        print("No file selected.")
    elif len(file_paths) == 1:
        is_single, vdom_data = parse_config_file(file_paths[0])
        if is_single:
            print("Nothing to compare (only one single-VDOM config selected).")
        else:
            file_vdom_map = {file_paths[0]: vdom_data}
            all_objects, col_labels, diffs = compare_objects_across_files(file_vdom_map)
            generate_html_report(all_objects, col_labels, diffs)
    else:
        file_vdom_map = {}
        for path in file_paths:
            _, vdom_data = parse_config_file(path)
            file_vdom_map[path] = vdom_data
        all_objects, col_labels, diffs = compare_objects_across_files(file_vdom_map)
        generate_html_report(all_objects, col_labels, diffs)
