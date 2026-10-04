#!/usr/bin/env python3
"""
nifi_flow_diff.py - Compare two Apache NiFi flow definitions and report the deltas.

Supported inputs (plain JSON or gzip, detected automatically):
  * "Download flow definition" exports    {"flowContents": ..., "parameterContexts": ...}
  * NiFi Registry snapshots                {"snapshotMetadata": ..., "flowContents": ...}
  * API responses wrapping a snapshot      {"versionedFlowSnapshot": {...}}
  * The instance flow file conf/flow.json.gz {"rootGroup": ..., "controllerServices": ...}
  * A bare VersionedProcessGroup           {"identifier": ..., "processors": [...], ...}

Components are matched by versioned identifier (default) or by group path + name
(--match-by name), which helps when the "same" flow was built separately in two
environments and the identifiers don't line up.

Exit status: 0 = no differences, 1 = differences found, 2 = error.

Examples:
  nifi_flow_diff.py old.json new.json
  nifi_flow_diff.py old.json new.json --ignore-position --type processor,connection
  nifi_flow_diff.py old.json new.json -o diff.html        # format inferred from extension
  nifi_flow_diff.py old.json new.json --format md -o diff.md
  nifi_flow_diff.py old.json new.json --format json | jq '.summary'
  nifi_flow_diff.py dev.json prod.json --match-by name --ignore 'properties.Password*'
"""

import argparse
import difflib
import fnmatch
import gzip
import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

__version__ = "1.1.0"

# (child list key inside a VersionedProcessGroup, display type)
CHILD_LISTS = [
    ("processors", "Processor"),
    ("inputPorts", "Input Port"),
    ("outputPorts", "Output Port"),
    ("funnels", "Funnel"),
    ("labels", "Label"),
    ("connections", "Connection"),
    ("controllerServices", "Controller Service"),
    ("remoteProcessGroups", "Remote Process Group"),
]
CHILD_KEYS = {k for k, _ in CHILD_LISTS} | {"processGroups"}

TYPE_ORDER = [
    "Parameter Context", "Parameter Provider", "Registry Client",
    "Controller Service", "Reporting Task", "Flow Analysis Rule",
    "Process Group", "Processor", "Input Port", "Output Port",
    "Remote Process Group", "Funnel", "Label", "Connection",
]
STATUS_ORDER = ["added", "removed", "modified", "moved"]

# Canvas-only fields: reported as "moved", never as configuration changes.
LAYOUT_FIELDS = ("position", "bends", "zIndex", "labelIndex", "width", "height")

# Fields that differ between otherwise-identical exports and carry no config meaning.
DEFAULT_IGNORES = [
    "instanceIdentifier", "*.instanceIdentifier",
    "instanceGroupId", "*.instanceGroupId",
    "componentType",
    "groupIdentifier",          # parent changes are reported as "relocated" instead
]
# propertyDescriptors is schema metadata that churns whenever a bundle version changes.
DESCRIPTOR_IGNORES = ["propertyDescriptors"]
# When matching by name, identifiers are expected to differ.
NAME_MODE_IGNORES = [
    "identifier", "versionedComponentId",
    "source.id", "source.groupId", "destination.id", "destination.groupId",
    "*.identifier",
]


# --------------------------------------------------------------------------- loading

def load_json(path):
    with open(path, "rb") as fh:
        magic = fh.read(2)
    opener = gzip.open if magic == b"\x1f\x8b" else open
    try:
        with opener(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: not valid JSON ({e})") from None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.values())
    return list(value)


def extract(doc):
    """Return (kind, root_group, {type: [components]}, [parameter contexts])."""
    if isinstance(doc, dict) and "versionedFlowSnapshot" in doc:
        doc = doc["versionedFlowSnapshot"]
    if not isinstance(doc, dict):
        raise ValueError("top-level JSON is not an object")

    if "flowContents" in doc:
        return ("flow definition", doc["flowContents"], {
            "Controller Service": _as_list(doc.get("externalControllerServices")),
            "Parameter Provider": _as_list(doc.get("parameterProviders")),
        }, _as_list(doc.get("parameterContexts")))

    if "rootGroup" in doc:
        return ("flow.json", doc["rootGroup"], {
            "Controller Service": _as_list(doc.get("controllerServices")),
            "Reporting Task": _as_list(doc.get("reportingTasks")),
            "Flow Analysis Rule": _as_list(doc.get("flowAnalysisRules")),
            "Parameter Provider": _as_list(doc.get("parameterProviders")),
            "Registry Client": _as_list(doc.get("registries")),
        }, _as_list(doc.get("parameterContexts")))

    if any(k in doc for k in ("processors", "processGroups", "connections")):
        return ("process group", doc, {}, [])

    raise ValueError("unrecognised format: expected flowContents, rootGroup, "
                     "or a process group with processors/processGroups/connections")


# --------------------------------------------------------------------------- indexing

def short_type(t):
    return t.rsplit(".", 1)[-1] if t else ""


def display_name(ctype, data):
    if ctype == "Connection":
        src, dst = data.get("source") or {}, data.get("destination") or {}
        rels = ",".join(sorted(data.get("selectedRelationships") or []))
        text = f"{src.get('name') or src.get('id', '?')} -> {dst.get('name') or dst.get('id', '?')}"
        if rels:
            text += f" [{rels}]"
        if data.get("name"):
            text = f"{data['name']}: {text}"
        return text
    if ctype == "Label":
        lines = (data.get("label") or "").strip().splitlines()
        return f'"{lines[0][:50]}"' if lines else "(empty label)"
    name = data.get("name") or ""
    st = short_type(data.get("type"))
    if st and st != name:
        return f"{name} ({st})" if name else st
    return name or data.get("identifier") or "?"


class FlowIndex:
    """Flattened, keyed view of every component in one flow file."""

    def __init__(self, path, match_by):
        self.path = path
        self.match_by = match_by
        self.kind, root, extras, pcs = extract(load_json(path))
        self.components = {}          # key -> record
        self.group_paths = {}         # group identifier -> "/A/B"
        self.cs_names = {}            # controller service id -> name
        self._seen = defaultdict(int)

        for pc in pcs:
            self._add("Parameter Context", pc, "(parameter contexts)", None, key_hint=pc.get("name"))
        for ctype, items in extras.items():
            for item in items:
                self._add(ctype, item, "(controller)", None)
        self._walk(root, "/", None, is_root=True)

    def _key(self, ctype, data, where, key_hint):
        if key_hint is not None:
            ident = key_hint
        elif self.match_by == "id":
            ident = data.get("identifier") or f"{where}|{display_name(ctype, data)}"
        else:
            ident = f"{where}|{display_name(ctype, data)}"
        key = (ctype, ident)
        self._seen[key] += 1
        if self._seen[key] > 1:                      # duplicate names in name mode
            key = (ctype, f"{ident}#{self._seen[key]}")
        return key

    def _add(self, ctype, data, where, parent_id, key_hint=None):
        key = self._key(ctype, data, where, key_hint)
        if ctype == "Controller Service" and data.get("identifier"):
            self.cs_names[data["identifier"]] = data.get("name") or data["identifier"]
        self.components[key] = {
            "type": ctype,
            "key": key,
            "id": data.get("identifier") or data.get("name"),
            "name": display_name(ctype, data),
            "where": where,
            "parent_id": parent_id,
            "data": data,
        }

    def _walk(self, group, path, parent_id, is_root=False):
        gid = group.get("identifier")
        self.group_paths[gid] = path
        gdata = {k: v for k, v in group.items() if k not in CHILD_KEYS}
        if is_root:
            self._add("Process Group", gdata, "", None, key_hint="<root>")
            self.components[("Process Group", "<root>")]["name"] = f"{group.get('name') or '(root)'} (root)"
        else:
            parent_path = path.rsplit("/", 1)[0] or "/"
            self._add("Process Group", gdata, parent_path, parent_id)
        for list_key, ctype in CHILD_LISTS:
            for child in group.get(list_key) or []:
                self._add(ctype, child, path, gid)
        for child in group.get("processGroups") or []:
            name = child.get("name") or child.get("identifier") or "?"
            self._walk(child, f"{path.rstrip('/')}/{name}", gid)

    def counts(self):
        c = defaultdict(int)
        for rec in self.components.values():
            c[rec["type"]] += 1
        return c


# --------------------------------------------------------------------------- diffing

def make_ignore(patterns):
    compiled = []
    for p in patterns:
        p = p.replace("[", "[[]")                   # treat [ literally, not as a char class
        compiled.extend([p, p + ".*", p + "[[]*"])  # match the field and everything under it
    return lambda path: any(fnmatch.fnmatchcase(path, p) for p in compiled)


def _scalar(v):
    return v is None or isinstance(v, (str, int, float, bool))


def _keyed(lst):
    """Turn a list of dicts into {name: item} when every item has a unique name/identifier."""
    if not all(isinstance(x, dict) for x in lst):
        return None
    for field in ("name", "identifier"):
        keys = [x.get(field) for x in lst]
        if all(k is not None for k in keys) and len(set(keys)) == len(keys):
            return {k: x for k, x in zip(keys, lst)}
    return None


def diff_values(a, b, path, out, ign, keyed_child=False):
    if a == b or (path and ign(path)):
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if keyed_child:
                p = f"{path}[{k}]"
            else:
                p = f"{path}.{k}" if path else str(k)
            if ign(p):
                continue
            if k not in a:
                out.append({"op": "added", "field": p, "old": None, "new": b[k]})
            elif k not in b:
                out.append({"op": "removed", "field": p, "old": a[k], "new": None})
            else:
                diff_values(a[k], b[k], p, out, ign)
        return
    if isinstance(a, list) and isinstance(b, list):
        ka, kb = _keyed(a), _keyed(b)
        if ka is not None and kb is not None and (a or b):
            diff_values(ka, kb, path, out, ign, keyed_child=True)
            return
        if all(_scalar(x) for x in a + b):
            sa, sb = set(a), set(b)
            if sa == sb:
                out.append({"op": "reordered", "field": path, "old": a, "new": b})
            else:
                for x in sorted(sa - sb, key=repr):
                    out.append({"op": "removed item", "field": path, "old": x, "new": None})
                for x in sorted(sb - sa, key=repr):
                    out.append({"op": "added item", "field": path, "old": None, "new": x})
            return
    out.append({"op": "changed", "field": path, "old": a, "new": b})


def _resolve_cs_refs(data, cs_names):
    """In name mode, show controller-service references by name so IDs don't cause noise."""
    props = data.get("properties")
    if not isinstance(props, dict) or not cs_names:
        return data
    data = dict(data)
    data["properties"] = {k: (f"<service: {cs_names[v]}>" if isinstance(v, str) and v in cs_names else v)
                          for k, v in props.items()}
    return data


def compare(left, right, ign, track_layout):
    changes = []
    for key in sorted(set(left.components) | set(right.components),
                      key=lambda k: (TYPE_ORDER.index(k[0]) if k[0] in TYPE_ORDER else 99, str(k[1]))):
        a, b = left.components.get(key), right.components.get(key)
        if a is None or b is None:
            rec = b or a
            changes.append({"status": "added" if a is None else "removed", "type": rec["type"],
                            "id": rec["id"], "name": rec["name"], "path": rec["where"], "fields": []})
            continue

        da, db = a["data"], b["data"]
        if left.match_by == "name":
            da, db = _resolve_cs_refs(da, left.cs_names), _resolve_cs_refs(db, right.cs_names)

        fields = []
        diff_values(da, db, "", fields, lambda p: ign(p) or p.split(".")[0].split("[")[0] in LAYOUT_FIELDS)

        if left.match_by == "id" and a["parent_id"] != b["parent_id"] and key[1] != "<root>":
            fields.insert(0, {"op": "relocated", "field": "(parent group)", "old": a["where"], "new": b["where"]})

        moved = None
        if track_layout:
            la = {f: da.get(f) for f in LAYOUT_FIELDS if f in da}
            lb = {f: db.get(f) for f in LAYOUT_FIELDS if f in db}
            if la != lb:
                moved = {"old": la.get("position"), "new": lb.get("position"),
                         "other": sorted(f for f in set(la) | set(lb) if f != "position" and la.get(f) != lb.get(f))}

        if fields or moved:
            if b["name"] != a["name"]:
                name = f"{a['name']}  =>  {b['name']}"
            else:
                name = b["name"]
            changes.append({"status": "modified" if fields else "moved", "type": key[0],
                            "id": b["id"], "name": name, "path": b["where"],
                            "fields": fields, "moved": moved})
    changes.sort(key=lambda c: (TYPE_ORDER.index(c["type"]) if c["type"] in TYPE_ORDER else 99,
                                c["path"], c["name"].lower()))
    return changes


def summarize(changes):
    summary = defaultdict(lambda: dict.fromkeys(STATUS_ORDER, 0))
    for c in changes:
        summary[c["type"]][c["status"]] += 1
    return {t: summary[t] for t in TYPE_ORDER if t in summary} | \
           {t: v for t, v in summary.items() if t not in TYPE_ORDER}


# --------------------------------------------------------------------------- rendering

class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


STATUS_STYLE = {"added": ("32", "+", "ADDED"), "removed": ("31", "-", "REMOVED"),
                "modified": ("33", "~", "MODIFIED"), "moved": ("36", ">", "MOVED")}


def fmt_value(v, max_len):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=False)
    if isinstance(v, str):
        s = "'" + s.replace("\n", "\\n") + "'"
    if max_len and len(s) > max_len:
        s = s[:max_len - 15] + f"...(+{len(s) - max_len + 15} chars)"
    return s


def is_long_text(field):
    return (isinstance(field["old"], str) and isinstance(field["new"], str)
            and ("\n" in field["old"] or "\n" in field["new"] or max(len(field["old"]), len(field["new"])) > 200))


def text_diff_lines(old, new, max_lines):
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "old", "new", n=2, lineterm=""))
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more diff lines)"]
    return lines


def fmt_pos(p):
    if not isinstance(p, dict):
        return "none"
    return f"({p.get('x', 0):.0f}, {p.get('y', 0):.0f})"


def describe_field(f, max_len):
    op = f["op"]
    if op == "changed":
        return f"{f['field']}: {fmt_value(f['old'], max_len)} -> {fmt_value(f['new'], max_len)}"
    if op == "relocated":
        return f"moved to another group: {f['old']} -> {f['new']}"
    if op == "reordered":
        return f"{f['field']}: order changed {fmt_value(f['old'], max_len)} -> {fmt_value(f['new'], max_len)}"
    if op in ("added", "added item"):
        return f"{f['field']}: + {fmt_value(f['new'], max_len)}"
    return f"{f['field']}: - {fmt_value(f['old'], max_len)}"


def describe_move(m):
    s = f"position {fmt_pos(m['old'])} -> {fmt_pos(m['new'])}" if m["old"] != m["new"] else "layout"
    if m["other"]:
        s += f" (also {', '.join(m['other'])})"
    return s


def summary_table(summary):
    rows = [("Type", "Added", "Removed", "Modified", "Moved")]
    totals = dict.fromkeys(STATUS_ORDER, 0)
    for t, c in summary.items():
        rows.append((t, *(str(c[s]) for s in STATUS_ORDER)))
        for s in STATUS_ORDER:
            totals[s] += c[s]
    rows.append(("Total", *(str(totals[s]) for s in STATUS_ORDER)))
    return rows


def render_text(result, args, style):
    out = []
    out.append(style("1", "NiFi flow diff"))
    for side in ("left", "right"):
        info = result[side]
        out.append(f"  {'A' if side == 'left' else 'B'}: {info['file']}  ({info['kind']}, {info['components']:,} components)")
    out.append(f"  matched by: {result['match_by']}")
    out.append("")

    if not result["changes"]:
        out.append(style("32", "No differences found."))
        return "\n".join(out)

    rows = summary_table(result["summary"])
    widths = [max(len(r[i]) for r in rows) for i in range(5)]
    out.append(style("1", "Summary"))
    for i, r in enumerate(rows):
        line = "  " + r[0].ljust(widths[0]) + "".join("  " + c.rjust(max(w, 8)) for c, w in zip(r[1:], widths[1:]))
        out.append(style("1", line) if i in (0, len(rows) - 1) else line)
    if args.summary:
        return "\n".join(out)

    current = None
    for c in result["changes"]:
        if c["type"] != current:
            current = c["type"]
            out.append("")
            out.append(style("1", f"== {current} =="))
        color, sym, label = STATUS_STYLE[c["status"]]
        where = f"{c['path']}  " if c["path"] else ""
        ident = style("2", f"  [{c['id']}]") if args.show_ids and c["id"] else ""
        out.append(style(color, f"{sym} {label:<8}") + f" {where}{style('1', c['name'])}{ident}")
        for f in c["fields"]:
            if is_long_text(f):
                out.append(f"      {f['field']}: (text changed)")
                for line in text_diff_lines(f["old"], f["new"], args.max_diff_lines):
                    col = "32" if line.startswith("+") else "31" if line.startswith("-") else "2"
                    out.append("          " + style(col, line))
            else:
                out.append("      " + describe_field(f, args.max_value_len))
        if c.get("moved") and c["status"] == "modified":
            out.append("      " + style("36", describe_move(c["moved"])))
        elif c.get("moved"):
            out[-1] += "  " + style("36", describe_move(c["moved"]))
    return "\n".join(out)


def md_escape(s):
    return str(s).replace("|", "\\|").replace("`", "'")


def render_markdown(result, args):
    out = ["# NiFi flow diff", "",
           f"- **A:** `{result['left']['file']}` ({result['left']['kind']}, {result['left']['components']:,} components)",
           f"- **B:** `{result['right']['file']}` ({result['right']['kind']}, {result['right']['components']:,} components)",
           f"- **Matched by:** {result['match_by']}", ""]
    if not result["changes"]:
        out.append("No differences found.")
        return "\n".join(out)
    rows = summary_table(result["summary"])
    out.append("## Summary\n")
    out.append("| " + " | ".join(rows[0]) + " |")
    out.append("|---|" + "---:|" * 4)
    for r in rows[1:]:
        cells = [md_escape(x) for x in r]
        if r[0] == "Total":
            cells = [f"**{x}**" for x in cells]
        out.append("| " + " | ".join(cells) + " |")
    if args.summary:
        return "\n".join(out)
    current = None
    for c in result["changes"]:
        if c["type"] != current:
            current = c["type"]
            out.append(f"\n## {current}\n")
        _, sym, label = STATUS_STYLE[c["status"]]
        where = f"`{md_escape(c['path'])}` " if c["path"] else ""
        ident = f" <sub>{c['id']}</sub>" if args.show_ids and c["id"] else ""
        out.append(f"- **{label}** {where}**{md_escape(c['name'])}**{ident}")
        for f in c["fields"]:
            if is_long_text(f):
                out.append(f"  - `{md_escape(f['field'])}` (text changed)")
                out.append("    ```diff")
                out.extend("    " + l for l in text_diff_lines(f["old"], f["new"], args.max_diff_lines))
                out.append("    ```")
            else:
                out.append(f"  - {md_escape(describe_field(f, args.max_value_len))}")
        if c.get("moved"):
            out.append(f"  - {describe_move(c['moved'])}")
    return "\n".join(out)


# Self-contained HTML report: inline CSS and a little vanilla JS (search box,
# status toggles, expand/collapse). No external files or network access, so it
# opens offline and can be emailed or attached as a single file. The report
# is fully readable with JavaScript disabled; the script only adds filtering.
HTML_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1f;--muted:#6b6b70;--line:#e2e2e0;--code:#f1f1ef;
--add:#1a7f37;--add-bg:#e6f4ea;--rem:#b42318;--rem-bg:#fde8e7;--mod:#9a6700;--mod-bg:#fff4d6;
--mov:#0b62a4;--mov-bg:#e3f0fb}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--fg:#e8e8ea;--muted:#9a9aa0;
--line:#323236;--code:#26262a;--add:#5fd38a;--add-bg:#163322;--rem:#ff8a80;--rem-bg:#3b1a19;
--mod:#f2c35b;--mod-bg:#3a2e12;--mov:#7cc0f5;--mov-bg:#12304a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 12px}
h2{font-size:17px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.meta{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0 0 20px;color:var(--muted)}
.meta b{color:var(--fg);font-weight:600}
.meta span{overflow-wrap:anywhere}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow-x:auto}
table.sum{border-collapse:collapse;width:100%;max-width:640px}
table.sum th,table.sum td{padding:6px 12px;border-bottom:1px solid var(--line);text-align:right}
table.sum th:first-child,table.sum td:first-child{text-align:left}
table.sum tr:last-child td{border-bottom:0;font-weight:600}
table.sum a{color:inherit}
td.zero{color:var(--muted)}
.toolbar{position:sticky;top:0;z-index:2;display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;
padding:10px 12px;margin:20px 0 0;background:var(--card);border:1px solid var(--line);border-radius:8px}
.toolbar input[type=search]{flex:1 1 220px;min-width:0;padding:6px 10px;border:1px solid var(--line);
border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
.toolbar label{white-space:nowrap;cursor:pointer}
.toolbar button{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit;cursor:pointer}
#count{color:var(--muted);margin-left:auto}
details.chg{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:6px;margin:6px 0}
details.added{border-left-color:var(--add)}details.removed{border-left-color:var(--rem)}
details.modified{border-left-color:var(--mod)}details.moved{border-left-color:var(--mov)}
summary{padding:7px 12px;cursor:pointer;display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}
summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B8";color:var(--muted);width:10px}
details[open]>summary::before{content:"\\25BE"}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;padding:1px 7px;border-radius:10px}
.added .badge{color:var(--add);background:var(--add-bg)}.removed .badge{color:var(--rem);background:var(--rem-bg)}
.modified .badge{color:var(--mod);background:var(--mod-bg)}.moved .badge{color:var(--mov);background:var(--mov-bg)}
.path{color:var(--muted)}.name{font-weight:600;overflow-wrap:anywhere}.cid{color:var(--muted);font-size:11.5px}
.body{padding:2px 12px 10px 34px}
table.fields{border-collapse:collapse;width:100%;table-layout:fixed}
table.fields th{text-align:left;color:var(--muted);font-weight:500;font-size:12px;padding:4px 8px;border-bottom:1px solid var(--line)}
table.fields td{vertical-align:top;padding:5px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
table.fields tr:last-child td{border-bottom:0}
table.fields col.f{width:28%}
.old{color:var(--rem)}.new{color:var(--add)}.op{color:var(--muted);font-size:12px}
pre.diff{margin:4px 0 0;padding:8px 10px;background:var(--code);border-radius:6px;overflow-x:auto;white-space:pre}
pre.diff .a{color:var(--add)}pre.diff .r{color:var(--rem)}pre.diff .h{color:var(--muted)}
.move{color:var(--mov);font-size:12.5px;margin-top:4px}
.empty{padding:16px;color:var(--add);font-weight:600}
.hidden{display:none!important}
@media print{.toolbar{display:none}details.chg{break-inside:avoid}}
"""

HTML_JS = """
(function(){
  var q=document.getElementById('q'), count=document.getElementById('count');
  var items=[].slice.call(document.querySelectorAll('details.chg'));
  var boxes=[].slice.call(document.querySelectorAll('input[data-status]'));
  var sections=[].slice.call(document.querySelectorAll('section.type'));
  function apply(){
    var term=q.value.toLowerCase().trim(), on={}, shown=0;
    boxes.forEach(function(b){on[b.dataset.status]=b.checked;});
    items.forEach(function(d){
      var ok=on[d.dataset.status] && (!term || d.textContent.toLowerCase().indexOf(term)>=0);
      d.classList.toggle('hidden',!ok); if(ok) shown++;
    });
    sections.forEach(function(s){s.classList.toggle('hidden',!s.querySelector('details.chg:not(.hidden)'));});
    count.textContent=shown+' of '+items.length+' shown';
  }
  q.addEventListener('input',apply);
  boxes.forEach(function(b){b.addEventListener('change',apply);});
  document.getElementById('expand').onclick=function(){items.forEach(function(d){d.open=true;});};
  document.getElementById('collapse').onclick=function(){items.forEach(function(d){d.open=false;});};
  apply();
})();
"""


def render_html(result, args):
    esc = html.escape
    left, right = result["left"], result["right"]
    changes = result["changes"]

    def anchor(t):
        return "t-" + "".join(ch if ch.isalnum() else "-" for ch in t.lower())

    def val(v):
        return esc(fmt_value(v, args.max_value_len))

    out = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>NiFi flow diff - {esc(os.path.basename(left['file']))} vs {esc(os.path.basename(right['file']))}</title>",
        f"<style>{HTML_CSS}</style></head><body><main>",
        "<h1>NiFi flow diff</h1>",
        '<div class="meta">',
        f"<b>A</b><span><code>{esc(left['file'])}</code> &middot; {esc(left['kind'])}, {left['components']:,} components</span>",
        f"<b>B</b><span><code>{esc(right['file'])}</code> &middot; {esc(right['kind'])}, {right['components']:,} components</span>",
        f"<b>Matched by</b><span>{esc(result['match_by'])}</span>",
        f"<b>Generated</b><span>{datetime.now():%Y-%m-%d %H:%M:%S} by nifi_flow_diff.py {__version__}</span>",
        "</div>",
    ]

    if not changes:
        out.append('<div class="card empty">No differences found.</div></main></body></html>')
        return "\n".join(out)

    # Summary table
    rows = summary_table(result["summary"])
    out.append('<div class="card"><table class="sum"><thead><tr>')
    out.extend(f"<th>{esc(h)}</th>" for h in rows[0])
    out.append("</tr></thead><tbody>")
    for r in rows[1:]:
        label = esc(r[0]) if r[0] == "Total" or args.summary else f'<a href="#{anchor(r[0])}">{esc(r[0])}</a>'
        cells = "".join(f'<td class="zero">{n}</td>' if n == "0" else f"<td>{n}</td>" for n in r[1:])
        out.append(f"<tr><td>{label}</td>{cells}</tr>")
    out.append("</tbody></table></div>")

    if args.summary:
        out.append("</main></body></html>")
        return "\n".join(out)

    # Toolbar (only does anything with JS enabled; harmless without it)
    present = [s for s in STATUS_ORDER if any(c["status"] == s for c in changes)]
    out.append('<div class="toolbar"><input id="q" type="search" placeholder="Filter by name, path, property, value...">')
    for s in present:
        out.append(f'<label><input type="checkbox" data-status="{s}" checked> {s}</label>')
    out.append('<button id="expand" type="button">Expand all</button>'
               '<button id="collapse" type="button">Collapse all</button><span id="count"></span></div>')

    # Details grouped by component type
    current = None
    for c in changes:
        if c["type"] != current:
            if current is not None:
                out.append("</section>")
            current = c["type"]
            out.append(f'<section class="type"><h2 id="{anchor(current)}">{esc(current)}</h2>')
        _, _, label = STATUS_STYLE[c["status"]]
        has_body = bool(c["fields"]) or (c.get("moved") and c["status"] == "modified")
        open_attr = " open" if has_body else ""
        out.append(f'<details class="chg {c["status"]}" data-status="{c["status"]}"{open_attr}><summary>'
                   f'<span class="badge">{label}</span>'
                   + (f'<span class="path mono">{esc(c["path"])}</span>' if c["path"] else "")
                   + f'<span class="name">{esc(c["name"])}</span>'
                   + (f'<span class="cid mono">{esc(str(c["id"]))}</span>' if args.show_ids and c["id"] else "")
                   + (f'<span class="move">{esc(describe_move(c["moved"]))}</span>'
                      if c.get("moved") and c["status"] == "moved" else "")
                   + "</summary>")
        if has_body:
            out.append('<div class="body">')
            if c["fields"]:
                out.append('<table class="fields"><colgroup><col class="f"><col><col></colgroup>'
                           "<thead><tr><th>Field</th><th>Old (A)</th><th>New (B)</th></tr></thead><tbody>")
                for f in c["fields"]:
                    field = f'<td class="mono">{esc(f["field"])}</td>'
                    op = f["op"]
                    if is_long_text(f):
                        lines = []
                        for line in text_diff_lines(f["old"], f["new"], args.max_diff_lines):
                            cls = ("h" if line.startswith(("---", "+++", "@@", "..."))
                                   else "a" if line.startswith("+") else "r" if line.startswith("-") else "")
                            lines.append(f'<span class="{cls}">{esc(line)}</span>' if cls else esc(line))
                        out.append(f'<tr>{field}<td colspan="2"><span class="op">text changed</span>'
                                   f'<pre class="diff">{chr(10).join(lines)}</pre></td></tr>')
                    elif op == "relocated":
                        out.append(f'<tr><td class="mono">(parent group)</td><td class="old mono">{esc(f["old"])}</td>'
                                   f'<td class="new mono">{esc(f["new"])}</td></tr>')
                    elif op in ("added", "added item"):
                        note = '<span class="op">item added</span><br>' if op == "added item" else ""
                        out.append(f'<tr>{field}<td class="op">(absent)</td><td class="new mono">{note}{val(f["new"])}</td></tr>')
                    elif op in ("removed", "removed item"):
                        note = '<span class="op">item removed</span><br>' if op == "removed item" else ""
                        out.append(f'<tr>{field}<td class="old mono">{note}{val(f["old"])}</td><td class="op">(absent)</td></tr>')
                    elif op == "reordered":
                        out.append(f'<tr>{field}<td class="old mono"><span class="op">order changed</span><br>{val(f["old"])}</td>'
                                   f'<td class="new mono">{val(f["new"])}</td></tr>')
                    else:
                        out.append(f'<tr>{field}<td class="old mono">{val(f["old"])}</td><td class="new mono">{val(f["new"])}</td></tr>')
                out.append("</tbody></table>")
            if c.get("moved") and c["status"] == "modified":
                out.append(f'<div class="move">Also moved: {esc(describe_move(c["moved"]))}</div>')
            out.append("</div>")
        out.append("</details>")
    out.append("</section>")
    out.append(f"<script>{HTML_JS}</script></main></body></html>")
    return "\n".join(out)


FORMAT_BY_EXTENSION = {".html": "html", ".htm": "html", ".md": "md", ".markdown": "md", ".json": "json"}


# --------------------------------------------------------------------------- CLI

def normalize_type(t):
    t = t.strip().lower().replace("_", " ").replace("-", " ")
    for real in TYPE_ORDER:
        r = real.lower()
        if t in (r, r + "s", r.replace(" ", ""), r.replace(" ", "") + "s"):
            return real
    aliases = {"pg": "Process Group", "cs": "Controller Service", "rpg": "Remote Process Group",
               "param": "Parameter Context", "params": "Parameter Context", "port": None, "ports": None}
    if t in aliases:
        return aliases[t]
    raise argparse.ArgumentTypeError(f"unknown component type '{t}'")


def build_parser():
    p = argparse.ArgumentParser(
        prog="nifi_flow_diff.py",
        description="Compare two NiFi flow definition JSON files and report added, removed, "
                    "modified and moved components.",
        epilog="Exit status: 0 no differences, 1 differences found, 2 error.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("old", help="baseline flow file (A)")
    p.add_argument("new", help="flow file to compare against the baseline (B)")
    p.add_argument("-f", "--format", choices=["text", "md", "json", "html"], default=None,
                   help="output format (default: text, or inferred from the -o extension: .html, .md, .json)")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("--match-by", choices=["id", "name"], default="id",
                   help="match components by versioned identifier (default) or by group path + name")
    p.add_argument("--ignore-position", action="store_true", help="don't report canvas moves (position, bends, label size)")
    p.add_argument("--include-descriptors", action="store_true",
                   help="also diff propertyDescriptors (ignored by default; mostly bundle-version noise)")
    p.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                   help="ignore fields matching this dotted-path glob, e.g. 'properties.Password*' "
                        "or '*.comments' (repeatable)")
    p.add_argument("--type", dest="types", default=None, metavar="LIST",
                   help="only report these component types, comma-separated "
                        "(e.g. processor,connection,controller-service,pg)")
    p.add_argument("--status", default=None, metavar="LIST",
                   help="only report these statuses, comma-separated (added,removed,modified,moved)")
    p.add_argument("--summary", action="store_true", help="print only the summary table")
    p.add_argument("--show-ids", action="store_true", help="show component identifiers")
    p.add_argument("--max-value-len", type=int, default=160, help="truncate values longer than this (0 = never; default 160)")
    p.add_argument("--max-diff-lines", type=int, default=60, help="cap unified-diff lines per text field (0 = no cap; default 60)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        types = None
        if args.types:
            types = set()
            for t in args.types.split(","):
                if t.strip().lower() in ("port", "ports"):
                    types |= {"Input Port", "Output Port"}
                else:
                    types.add(normalize_type(t))
        statuses = None
        if args.status:
            statuses = {s.strip().lower() for s in args.status.split(",")}
            bad = statuses - set(STATUS_ORDER)
            if bad:
                raise argparse.ArgumentTypeError(f"unknown status: {', '.join(sorted(bad))}")

        left = FlowIndex(args.old, args.match_by)
        right = FlowIndex(args.new, args.match_by)

        patterns = DEFAULT_IGNORES + args.ignore
        if not args.include_descriptors:
            patterns += DESCRIPTOR_IGNORES
        if args.match_by == "name":
            patterns += NAME_MODE_IGNORES
        changes = compare(left, right, make_ignore(patterns), track_layout=not args.ignore_position)
    except (OSError, ValueError, argparse.ArgumentTypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if types:
        changes = [c for c in changes if c["type"] in types]
    if statuses:
        changes = [c for c in changes if c["status"] in statuses]

    result = {
        "left": {"file": args.old, "kind": left.kind, "components": len(left.components)},
        "right": {"file": args.new, "kind": right.kind, "components": len(right.components)},
        "match_by": args.match_by,
        "summary": summarize(changes),
        "changes": changes,
    }

    fmt = args.format
    if fmt is None:
        ext = os.path.splitext(args.output)[1].lower() if args.output else ""
        fmt = FORMAT_BY_EXTENSION.get(ext, "text")

    if fmt == "json":
        report = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    elif fmt == "md":
        report = render_markdown(result, args)
    elif fmt == "html":
        report = render_html(result, args)
    else:
        use_color = not args.no_color and not args.output and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        report = render_text(result, args, Style(use_color))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as e:
            print(f"error: cannot write {args.output}: {e}", file=sys.stderr)
            return 2
        print(f"{fmt.upper()} report written to {args.output} ({len(changes)} changed components)", file=sys.stderr)
    else:
        print(report)
    return 1 if changes else 0


if __name__ == "__main__":
    sys.exit(main())
