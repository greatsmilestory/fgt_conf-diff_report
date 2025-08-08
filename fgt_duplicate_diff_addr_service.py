import re
import html
import tkinter as tk
from tkinter import filedialog
import webbrowser
import os


# GUI function for user to select multiple FortiGate config files
def select_files():
    root = tk.Tk()
    root.withdraw()  # Hide the default Tkinter window
    file_paths = filedialog.askopenfilenames(
        title="Select FortiGate Config Files",
        filetypes=[("Config files", "*.conf *.txt"), ("All files", "*.*")]
    )
    return list(file_paths)


# Check if "config vdom" string is missing in config text to determine single VDOM
def is_single_vdom(config_text):
    return "config vdom" not in config_text


# Extract firewall-related objects (address, addrgrp, etc.) from config blocks
def extract_firewall_objects(text):
    firewall_pattern = re.compile(r'(config firewall .+?)(?=config|end\s+config|\Z)', re.S)  # Extract each config firewall block
    object_pattern = re.compile(r'edit "(.+?)"(.*?)next', re.S)  # Extract object name and content
    set_pattern = re.compile(r'set (\S+) (.+)')  # Extract properties set by set command

    firewalls = {}
    for fw_block in firewall_pattern.findall(text):
        fw_type = fw_block.split("\n")[0].strip()  # e.g., config firewall address
        objects = {}
        for obj_name, obj_content in object_pattern.findall(fw_block):
            props = {}
            for key, val in set_pattern.findall(obj_content):
                if key.lower() in ["uuid", "associated-interface"]:
                    continue  # Exclude ignored properties
                if key.lower() == "member":
                    items = re.findall(r'"([^"]*)"', val)
                    val = " ".join(f'"{item}"' for item in sorted(items))  # Compose sorted string
                else:
                    val = val.strip('"')
                    if key.lower() == "comment":
                        val = " ".join(val.split())  # Remove multi-line comments to single line
                props[key] = val
            objects[obj_name] = props
        firewalls[fw_type] = objects
    return firewalls


# Extract objects by VDOM from config file
def parse_config_file(file_path):
    with open(file_path, encoding="utf-8", errors="ignore") as f:
        config_text = f.read()

    is_single = is_single_vdom(config_text)
    vdom_data = {}

    if is_single:
        vdom_name = "root"  # Set VDOM name as "root" if single VDOM
        vdom_data[vdom_name] = extract_firewall_objects(config_text)
    else:
        vdom_start_pattern = re.compile(r'edit (\S+)\s+config system object-tagging', re.S)  # Find VDOM sections
        matches = list(vdom_start_pattern.finditer(config_text))

        for idx, match in enumerate(matches):
            vdom_name = match.group(1)
            start_pos = match.start()
            end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(config_text)
            vdom_content = config_text[start_pos:end_pos]
            vdom_data[vdom_name] = extract_firewall_objects(vdom_content)

    return is_single, vdom_data


# Color mapping by object type (for HTML table distinction)
OBJ_COLOR_MAP = {
    "config firewall address": "#e0f7fa",
    "config firewall addrgrp": "#fff3e0",
    "config firewall service custom": "#e8f5e9",
    "config firewall service group": "#f3e5f5"
}

# Priority order for comparison
OBJ_TYPE_ORDER = [
    "config firewall address",
    "config firewall addrgrp",
    "config firewall service custom",
    "config firewall service group"
]


# Perform object comparison across multiple files and VDOMs
def compare_objects_across_files(file_vdom_map):
    all_objects = {}  # (fw_type, obj_name) => {label: props}
    col_labels = []   # Table column names: filename + [VDOM]

    # Create labels per file and VDOM
    for file_path, vdoms in file_vdom_map.items():
        file_label = os.path.basename(file_path)
        for vdom in vdoms.keys():
            label = f"{file_label}\n[{vdom}]"
            col_labels.append(label)

    # Collect all objects
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

            if len(values) < 2:
                continue  # Less than 2 items to compare
            if len(set(values.values())) <= 1:
                continue  # All values identical

            obj_diff[prop] = values

        if obj_diff:
            diffs[(fw_type, obj_name)] = obj_diff

    return all_objects, col_labels, diffs


# Highlight properties with duplicate values by color; unique values in red
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

    # Assign colors per item
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


# Generate HTML report for comparison results
def generate_html_report(all_objects, col_labels, diffs, output_file="report_fgt_duplicate_diff_addr_service.html"):
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

    # Mouse hover effect controlled by JS only
    extra_js = """
    <script>
    document.addEventListener("DOMContentLoaded", function() {
        const hoverItems = document.querySelectorAll(".hover-item");
        hoverItems.forEach(item => {
            item.addEventListener("mouseenter", () => {
                const val = item.getAttribute("data-val");
                const row = item.getAttribute("data-row");
                hoverItems.forEach(i => {
                    if (i.getAttribute("data-val") === val && i.getAttribute("data-row") === row) {
                        // Controlling mouse hover styles with JS: zoom, text shadows, borders, etc.
                        // i.style.display = "inline-block";
                        // i.style.transition = "transform 0.3s ease";
                        // i.style.backgroundColor = "transparent";
                        i.style.transform = "scale(1.15)";
                        /*
                         i.style.textShadow =
                            "0 0 5px #ffeb3b," +
                            "0 0 10px #ffeb3b," +
                            "0 0 20px #ffeb3b," +
                            "0 0 30px #fbc02d," +
                            "0 0 40px #fbc02d";
                        */
                        i.style.fontWeight = "bold";
                        i.style.border = "1px solid #0000ff";
                        i.style.borderRadius = "4px";
                        i.style.padding = "1px 3px";
                    }
                });
            });
            item.addEventListener("mouseleave", () => {
                hoverItems.forEach(i => {
                    // Reset mouse hover style
                    // i.style.display = "";
                    // i.style.transition = "";
                    // i.style.backgroundColor = "";
                    i.style.transform = "";
                    i.style.textShadow = "";
                    i.style.fontWeight = "";
                    i.style.border = "";
                    i.style.borderRadius = "";
                    i.style.padding = "";
                });
            });
        });
    });
    </script>
    """
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
            line-height: 1.6;
            font-family: "Malgun Gothic", Arial, sans-serif;
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
        <h3>FGT config files VDOM object comparison (Duplicate values colored, unique values in red)</h3>
        <div id="legend-container"><strong>File column color legend: </strong>
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

    # Fill table content
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

            # ★ Calculate duplicate colors once for all columns (also get duplicate item info)
            highlighted_vals, duplicate_items = highlight_differences_across_vdoms(values)

            # Wrapper for hover-item span with color (only for duplicate values)
            def wrap_hover_spans_with_color(text, rownum, duplicate_items):
                span_pattern = re.compile(r'(<span style="background-color:[^"]+">"([^"]*)"</span>)')
                result = []
                idx = 0
                for m in span_pattern.finditer(text):
                    start, end = m.span()
                    if start > idx:
                        raw = text[idx:start]
                        result.append(raw)
                    full_span = m.group(1)
                    val = m.group(2)
                    # Add hover-item class only for duplicates
                    if val in duplicate_items:
                        wrapped_span = f'<span class="hover-item" data-val="{html.escape(val)}" data-row="{rownum}">{full_span}</span>'
                    else:
                        wrapped_span = full_span
                    result.append(wrapped_span)
                    idx = end
                if idx < len(text):
                    result.append(text[idx:])
                return "".join(result)

            for label in col_labels:
                obj_props = all_objects.get((fw_type, obj_name), {}).get(label, None)
                val = values.get(label, "")
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
                html_content += f'<td class="vdom-column {cell_class}">{cell_text}</td>'
            html_content += "</tr>"
        row_num += 1

    html_content += "</tbody></table>"
    html_content += extra_js
    html_content += "</body></html>"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report generated: {output_file}")
    webbrowser.open(output_file)


# Main execution: select files → parse → compare → generate HTML report
if __name__ == "__main__":
    file_paths = select_files()

    if not file_paths:
        print("No files selected.")
    elif len(file_paths) == 1:
        is_single, vdom_data = parse_config_file(file_paths[0])
        if is_single:
            print("No comparison possible (only one single VDOM config file selected).")
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
