#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Streamlit SBOM → NOTICE generator
- Upload SPDX JSON (incl. SPDX-Lite) and/or CycloneDX JSON.
- Two buttons:
  1) Offline mode: "Generate (from scanned SBOM only)"
     *Produces NOTICE.md without external network calls.*
  2) Online mode: "Generate (fetch from internet)"
     *Fetches SPDX license texts and package artifacts (npm/PyPI/Maven/NuGet/RubyGems/Golang)
      to enrich license texts & copyrights.*

Disclaimer: This automates attribution but is not legal advice—review final NOTICE for completeness.
"""

import io
import json
import os
import re
import tarfile
import zipfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests
import streamlit as st
from packaging.version import parse as parse_version
from requests.utils import quote  # for URL-encoding module paths (Go proxy)

# --------------------------- Constants ---------------------------

NOASSERT = {"NOASSERTION", "NONE", None, ""}
CDX_URL_TYPES = {"website", "vcs", "distribution", "documentation", "release-notes"}
LICENSE_FILENAMES = [
    "LICENSE", "LICENSE.txt", "LICENSE.md",
    "COPYING", "COPYRIGHT", "NOTICE",
    "COPYING.txt", "COPYRIGHT.txt", "NOTICE.txt",
]
SPDX_LICENSE_TEXT_URL = "https://raw.githubusercontent.com/spdx/license-list-data/master/text/{id}.txt"
REQ_TIMEOUT = 20

# ------------------------ Streamlit UI ---------------------------

st.set_page_config(page_title="SBOM → NOTICE generator", page_icon="🧾", layout="centered")
st.title("🧾 SBOM → NOTICE generator")

st.markdown("""
Upload **SPDX JSON** (including SPDX‑Lite) and/or **CycloneDX JSON**.
Then choose either:
- **🗂️ Generate (from scanned SBOM only)** — uses SBOM content only *(offline)*.
- **🌐 Generate (fetch from internet)** — enriches with SPDX License List & package artifacts *(online)*.
""")

uploaded_files = st.file_uploader(
    "Upload one or more SBOM files (SPDX JSON or CycloneDX JSON)",
    accept_multiple_files=True,
    type=["json"],
)

include_spdx_texts = st.checkbox(
    "Include SPDX extracted license texts from SBOM (if present)",
    value=True,
    help="Appends texts from `hasExtractedLicensingInfos` to NOTICE (offline & online modes)."
)

output_title = st.text_input("NOTICE title", value="Open Source Notices")

col1, col2 = st.columns(2)
go_offline = col1.button("🗂️ Generate (from scanned SBOM only)", type="primary", disabled=not uploaded_files)
go_online  = col2.button("🌐 Generate (fetch from internet)", type="secondary", disabled=not uploaded_files)

st.caption("""
**Tip:** Offline mode never calls external APIs.  
Online mode fetches canonical SPDX license texts and attempts to download published artifacts (npm/PyPI/Maven/NuGet/RubyGems/Go) to extract `LICENSE` / `NOTICE` / `COPYRIGHT`.
""")

# ------------------------ Helpers -------------------------------

def normalize(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = str(s).strip()
    if not s or s.upper() in NOASSERT:
        return None
    return " ".join(s.split())

def detect_format(doc: dict) -> str:
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
            return "cdx"
        if doc.get("spdxVersion") or doc.get("SPDXID") or "packages" in doc or "files" in doc:
            return "spdx"
    return "unknown"

def choose_spdx_license(pkg: dict) -> Optional[str]:
    for key in ("licenseConcluded", "licenseDeclared"):
        val = normalize(pkg.get(key))
        if val:
            return val
    infos = pkg.get("licenseInfoFromFiles") or []
    items = [normalize(x) for x in infos if normalize(x)]
    items = sorted(set(items))
    return " AND ".join(items) if items else None

def resolve_spdx_urls(pkg: dict) -> Tuple[Optional[str], Optional[str]]:
    source_url = None
    dl = normalize(pkg.get("downloadLocation"))
    if dl and (dl.startswith(("http://","https://","git@","git+")) or dl.startswith("scm:")):
        source_url = dl
    if not source_url:
        homepage = normalize(pkg.get("homepage"))
        if homepage:
            source_url = homepage
    purl = None
    for ref in pkg.get("externalRefs") or []:
        rtype = (ref.get("referenceType") or "").lower()
        locator = normalize(ref.get("referenceLocator"))
        if "purl" in rtype and locator:
            purl = locator; break
        if not source_url and locator and locator.startswith(("http://","https://","git@","git+")):
            source_url = locator
    return source_url, purl

def parse_spdx(doc: dict) -> Tuple[List[dict], Dict[str,str]]:
    comps, license_texts = [], {}
    # SPDX extracted license texts (if present)
    for lic in doc.get("hasExtractedLicensingInfos") or []:
        lid = normalize(lic.get("licenseId")); text = lic.get("extractedText")
        if lid and text:
            license_texts[lid] = text

    pkgs = doc.get("packages") or []
    if pkgs:
        for pkg in pkgs:
            name = normalize(pkg.get("name"))
            if not name:
                continue
            version = normalize(pkg.get("versionInfo"))
            license_str = choose_spdx_license(pkg)
            cpr = normalize(pkg.get("copyrightText"))
            if cpr in NOASSERT:
                cpr = None
            src_url, purl = resolve_spdx_urls(pkg)
            comps.append({
                "name": name, "version": version, "license": license_str,
                "copyright": cpr, "source_url": src_url,
                "purl": purl, "source": "spdx", "provenance": {}
            })
        return comps, license_texts

    # SPDX-Lite fallback: aggregate from files[]
    files = doc.get("files") or []
    if files:
        doc_name = normalize(doc.get("name")) or normalize(doc.get("documentName")) or "SPDX-Document"
        lic_tokens, cpr_lines = set(), []
        for f in files:
            v = normalize(f.get("licenseConcluded"))
            if v: lic_tokens.add(v)
            for vv in f.get("licenseInfoInFile") or []:
                v2 = normalize(vv)
                if v2: lic_tokens.add(v2)
            cpr = normalize(f.get("copyrightText"))
            if cpr and cpr not in NOASSERT:
                cpr_lines.append(cpr)
        license_str = " AND ".join(sorted(lic_tokens)) if lic_tokens else None
        copyright_agg = " | ".join(sorted(set(cpr_lines))) if cpr_lines else None
        comps.append({
            "name": doc_name, "version": None, "license": license_str,
            "copyright": copyright_agg,
            "source_url": None, "purl": None,
            "source": "spdx", "provenance": {"aggregated_from_files": True}
        })
    return comps, license_texts

def parse_cyclonedx(doc: dict) -> List[dict]:
    comps = []
    for c in doc.get("components") or []:
        name = normalize(c.get("name"))
        if not name:
            continue
        version = normalize(c.get("version"))
        purl = normalize(c.get("purl"))

        license_str = None
        licenses = c.get("licenses") or []
        exprs = [normalize(x.get("expression")) for x in licenses if isinstance(x, dict) and x.get("expression")]
        exprs = [x for x in exprs if x]
        if exprs:
            license_str = exprs[0]
        else:
            ids_or_names = []
            for entry in licenses:
                lic = entry.get("license") if isinstance(entry, dict) else None
                if isinstance(lic, dict):
                    lid = normalize(lic.get("id")); lname = normalize(lic.get("name"))
                    if lid: ids_or_names.append(lid)
                    elif lname: ids_or_names.append(lname)
            ids_or_names = sorted(set(ids_or_names))
            if ids_or_names:
                license_str = " AND ".join(ids_or_names)

        source_url = None
        for ref in c.get("externalReferences") or []:
            rtype = (ref.get("type") or "").lower(); url = normalize(ref.get("url"))
            if rtype in CDX_URL_TYPES and url:
                source_url = url; break
        cpr = normalize(c.get("copyright"))

        comps.append({
            "name": name, "version": version, "license": license_str,
            "copyright": cpr, "source_url": source_url,
            "purl": purl, "source": "cdx", "provenance": {}
        })
    return comps

def key_of(c: dict) -> Tuple[str,str]:
    if c.get("purl"):
        return ("purl", c["purl"])
    return ("nv", f"{(c.get('name') or '').lower()}@{(c.get('version') or '').lower()}")

def dedupe_merge(components: List[dict]) -> List[dict]:
    merged = {}
    for c in components:
        k = key_of(c)
        if k not in merged:
            merged[k] = c.copy()
            continue
        ex = merged[k]
        for fld in ("name","version","license","copyright","source_url","purl"):
            cur, src_cur = c.get(fld), c.get("source")
            old, src_old = ex.get(fld), ex.get("source")
            if old:
                if cur and src_cur=="spdx" and src_old!="spdx":
                    ex[fld] = cur
            else:
                if cur: ex[fld] = cur
        ex["provenance"].update(c.get("provenance") or {})
        if ex.get("source")!="spdx" and c.get("source")=="spdx":
            ex["source"]="spdx"
    res = list(merged.values())
    res.sort(key=lambda x: ((x.get("name") or "").lower(), x.get("version") or ""))
    return res

@st.cache_data(show_spinner=False)
def fetch_spdx_text(license_id: str) -> Optional[str]:
    try:
        url = SPDX_LICENSE_TEXT_URL.format(id=license_id)
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code == 200 and r.text.strip():
            return r.text
    except Exception:
        pass
    return None

def split_license_expression(expr: str) -> List[str]:
    if not expr: return []
    tokens = re.split(r'[^A-Za-z0-9\.\-\+]+', expr)
    return [t for t in tokens if t]

def extract_texts_from_archive_bytes(buf: bytes) -> Dict[str,str]:
    texts = {}
    # Try tar archives (npm tgz or sdist tar.gz / RubyGems inner tar)
    try:
        fileobj = io.BytesIO(buf)
        with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
            for m in tf.getmembers():
                nm = os.path.basename(m.name)
                if nm.upper().startswith(("LICENSE","NOTICE","COPYING","COPYRIGHT")) and m.isfile():
                    f = tf.extractfile(m)
                    if f:
                        data = f.read().decode("utf-8", errors="replace").strip()
                        if data:
                            texts[nm] = data
        if texts: return texts
    except Exception:
        pass
    # Try zip/jar archives (Maven, NuGet, Go module zip)
    try:
        with zipfile.ZipFile(io.BytesIO(buf)) as zf:
            for nm in zf.namelist():
                base = os.path.basename(nm)
                up = base.upper()
                if up.startswith(("LICENSE","NOTICE","COPYING","COPYRIGHT")) or "LICENSE" in up or "NOTICE" in up or "COPYRIGHT" in up or "COPYING" in up or "META-INF" in up:
                    with zf.open(nm) as f:
                        data = f.read().decode("utf-8", errors="replace").strip()
                        if data:
                            texts[base] = data
        if texts: return texts
    except Exception:
        pass
    return texts

# ---------- Ecosystem fetchers (Online Mode) ----------

@st.cache_data(show_spinner=False)
def fetch_npm_license_texts(name: str, version: Optional[str]) -> Dict[str,str]:
    texts = {}
    try:
        url = f"https://registry.npmjs.org/{name}/{version or ''}"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code != 200: return texts
        meta = r.json()
        tarball = meta.get("dist",{}).get("tarball")
        if not tarball and "versions" in meta and version:
            tarball = meta["versions"].get(version,{}).get("dist",{}).get("tarball")
        if tarball:
            tr = requests.get(tarball, timeout=REQ_TIMEOUT)
            if tr.status_code==200:
                texts.update(extract_texts_from_archive_bytes(tr.content))
    except Exception:
        pass
    return texts

@st.cache_data(show_spinner=False)
def fetch_pypi_license_texts(name: str, version: Optional[str]) -> Dict[str,str]:
    texts = {}
    try:
        ver = version or ""
        url = f"https://pypi.org/pypi/{name}/{ver}/json" if ver else f"https://pypi.org/pypi/{name}/json"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code != 200: return texts
        meta = r.json()
        urls = meta.get("urls", [])
        sdist = next((u for u in urls if (u.get("packagetype")=="sdist")), None)
        dl = (sdist or (urls[0] if urls else None))
        if dl and dl.get("url"):
            tr = requests.get(dl["url"], timeout=REQ_TIMEOUT)
            if tr.status_code==200:
                texts.update(extract_texts_from_archive_bytes(tr.content))
    except Exception:
        pass
    return texts

@st.cache_data(show_spinner=False)
def fetch_maven_license_texts(group: str, artifact: str, version: str) -> Dict[str,str]:
    texts = {}
    try:
        base = f"https://repo1.maven.org/maven2/{group.replace('.','/')}/{artifact}/{version}"
        url = f"{base}/{artifact}-{version}-sources.jar"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code==200:
            texts.update(extract_texts_from_archive_bytes(r.content))
        else:
            url = f"{base}/{artifact}-{version}.jar"
            r = requests.get(url, timeout=REQ_TIMEOUT)
            if r.status_code==200:
                texts.update(extract_texts_from_archive_bytes(r.content))
    except Exception:
        pass
    return texts

@st.cache_data(show_spinner=False)
def fetch_nuget_license_texts(name: str, version: Optional[str]) -> Dict[str,str]:
    """
    NuGet v3 flat container: https://api.nuget.org/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg
    .nupkg is a ZIP; license files typically included in package content.
    """
    texts = {}
    try:
        if not version: return texts
        lower = name.lower()
        url = f"https://api.nuget.org/v3-flatcontainer/{lower}/{version}/{lower}.{version}.nupkg"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            texts.update(extract_texts_from_archive_bytes(r.content))
    except Exception:
        pass
    return texts

@st.cache_data(show_spinner=False)
def fetch_rubygems_license_texts(name: str, version: Optional[str]) -> Dict[str,str]:
    """
    RubyGems download URL: https://rubygems.org/downloads/<name>-<version>.gem
    .gem is a tar containing metadata.gz and data.tar.gz; license files in data.tar.gz.
    """
    texts = {}
    try:
        if not version: return texts
        url = f"https://rubygems.org/downloads/{name}-{version}.gem"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code != 200: return texts
        # .gem is a tar; open and find data.tar.gz
        fileobj = io.BytesIO(r.content)
        with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
            for m in tf.getmembers():
                if os.path.basename(m.name).endswith("data.tar.gz"):
                    f = tf.extractfile(m)
                    if not f: continue
                    buf = f.read()
                    # open nested tar.gz
                    inner = io.BytesIO(buf)
                    with tarfile.open(fileobj=inner, mode="r:*") as inner_tf:
                        for im in inner_tf.getmembers():
                            base = os.path.basename(im.name)
                            if base.upper().startswith(("LICENSE","NOTICE","COPYING","COPYRIGHT")) and im.isfile():
                                cf = inner_tf.extractfile(im)
                                if cf:
                                    data = cf.read().decode("utf-8", errors="replace").strip()
                                    if data:
                                        texts[base] = data
        return texts
    except Exception:
        pass
    return texts

@st.cache_data(show_spinner=False)
def fetch_golang_license_texts(module_path: str, version: Optional[str]) -> Dict[str,str]:
    """
    Go proxy zip: https://proxy.golang.org/<module>/@v/<version>.zip
    The zip contains the module source; license files typically at root or submodules.
    """
    texts = {}
    try:
        if not version: return texts
        # URL-encode module path (keep slashes)
        mod_encoded = quote(module_path, safe="/")
        url = f"https://proxy.golang.org/{mod_encoded}/@v/{version}.zip"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            texts.update(extract_texts_from_archive_bytes(r.content))
    except Exception:
        pass
    return texts

@st.cache_data(show_spinner=False)
def fetch_github_license(repo_url: str) -> Dict[str,str]:
    texts = {}
    try:
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", repo_url)
        if not m: return texts
        org, repo = m.group(1), m.group(2).replace(".git","")
        for fname in ("LICENSE","LICENSE.txt","COPYING","NOTICE","COPYRIGHT"):
            for branch in ("HEAD","main","master"):
                raw = f"https://raw.githubusercontent.com/{org}/{repo}/{branch}/{fname}"
                r = requests.get(raw, timeout=REQ_TIMEOUT)
                if r.status_code==200 and r.text.strip():
                    texts[fname] = r.text.strip()
                    return texts
    except Exception:
        pass
    return texts

def fetch_license_texts_by_purl(purl: Optional[str], name: Optional[str], version: Optional[str], source_url: Optional[str]) -> Dict[str,str]:
    texts = {}
    try:
        if purl and purl.startswith("pkg:npm/"):
            pkg = purl.split("/",2)[-1]
            pkg = pkg.split("@")[0] if "@" in pkg else pkg
            ver = version or (purl.split("@")[-1] if "@" in purl else None)
            texts.update(fetch_npm_license_texts(pkg, ver))
        elif purl and purl.startswith("pkg:pypi/"):
            pkg = purl.split("/",2)[-1].split("@")[0]
            ver = version or (purl.split("@")[-1] if "@" in purl else None)
            texts.update(fetch_pypi_license_texts(pkg, ver))
        elif purl and purl.startswith("pkg:maven/"):
            rest = purl[len("pkg:maven/"):]
            parts = rest.split("@")[0].split("/")
            if len(parts)>=2 and version:
                group, artifact = parts[0], parts[1]
                texts.update(fetch_maven_license_texts(group, artifact, version))
        elif purl and purl.startswith("pkg:nuget/"):
            pkg = purl.split("/",2)[-1]
            pkg = pkg.split("@")[0] if "@" in pkg else pkg
            ver = version or (purl.split("@")[-1] if "@" in purl else None)
            texts.update(fetch_nuget_license_texts(pkg, ver))
        elif purl and purl.startswith("pkg:gem/"):
            pkg = purl.split("/",2)[-1]
            pkg = pkg.split("@")[0] if "@" in pkg else pkg
            ver = version or (purl.split("@")[-1] if "@" in purl else None)
            texts.update(fetch_rubygems_license_texts(pkg, ver))
        elif purl and purl.startswith("pkg:golang/"):
            # module path may include slashes
            rest = purl[len("pkg:golang/"):]
            module = rest.split("@")[0]
            ver = version or (purl.split("@")[-1] if "@" in purl else None)
            texts.update(fetch_golang_license_texts(module, ver))

        # Fallback via GitHub repo URL (if provided)
        if not texts and source_url and "github.com" in source_url:
            texts.update(fetch_github_license(source_url))
    except Exception:
        pass
    return texts

def extract_copyright_lines(text: str, max_lines: int = 8) -> Optional[str]:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    picked = []
    for ln in lines:
        if ("copyright" in ln.lower()) or ("©" in ln):
            picked.append(ln)
        if len(picked) >= max_lines:
            break
    return " | ".join(picked) if picked else None

def render_md(components: List[dict], title: str, license_texts_map: Dict[str,str]) -> str:
    lines = []
    lines.append(f"# {title.strip() or 'Open Source Notices'}")
    lines.append(f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n")
    for c in components:
        nv = c.get("name") or ""
        if c.get("version"): nv += f" {c['version']}"
        lines.append(f"### {nv}")
        if c.get("license"): lines.append(f"- **License:** {c['license']}")
        if c.get("copyright"):
            lines.append(f"- **Copyright:** {c['copyright']}")
        if c.get("source_url"): lines.append(f"- **Source:** {c['source_url']}")
        if c.get("purl"): lines.append(f"- **PURL:** `{c['purl']}`")
        prov = c.get("provenance") or {}
        if prov.get("license_sources"):
            lines.append(f"- _License files_: {', '.join(prov['license_sources'])}")
        if prov.get("copyright_source"):
            lines.append(f"- _Copyright source_: {prov['copyright_source']}")
        lines.append("")
    if license_texts_map:
        lines.append("\n## License Texts\n")
        for k, v in license_texts_map.items():
            lines.append(f"### {k}\n```text\n{v.strip()}\n```\n")
    return "\n".join(lines).rstrip() + "\n"

# ------------------------ Processing ----------------------------

def process_sboms(uploaded_files) -> Tuple[List[dict], Dict[str,str]]:
    """Parse all uploaded files → (components, embedded_spdx_texts)"""
    all_components: List[dict] = []
    embedded_spdx_texts: Dict[str,str] = {}

    for uf in uploaded_files:
        try:
            doc = json.load(io.TextIOWrapper(uf, encoding="utf-8"))
        except Exception as e:
            st.warning(f"Failed to parse JSON: {uf.name} ({e})")
            continue

        kind = detect_format(doc)
        if kind=="spdx":
            comps, lic_texts = parse_spdx(doc)
            all_components.extend(comps)
            for k,v in lic_texts.items():
                embedded_spdx_texts.setdefault(k, v)
        elif kind=="cdx":
            all_components.extend(parse_cyclonedx(doc))
        else:
            st.warning(f"Unknown SBOM format for {uf.name}; skipping.")
    return all_components, embedded_spdx_texts

def generate_notice_offline(uploaded_files, title: str, include_spdx_texts: bool) -> str:
    """Offline path: no external APIs; SBOM-only + embedded SPDX texts."""
    comps, lic_texts_map = process_sboms(uploaded_files)
    if not comps:
        st.error("No components found across the uploaded files.")
        return ""

    merged = dedupe_merge(comps)

    appended_texts: Dict[str,str] = {}
    if include_spdx_texts and lic_texts_map:
        # Only append texts actually referenced by license expressions
        used_ids = set()
        for c in merged:
            lic = c.get("license") or ""
            tokens = split_license_expression(lic)
            for t in tokens:
                if t in lic_texts_map:
                    used_ids.add(t)
        for lid in sorted(used_ids):
            appended_texts[lid] = lic_texts_map[lid]

    return render_md(merged, title, appended_texts)

def generate_notice_online(uploaded_files, title: str, include_spdx_texts: bool) -> str:
    """Online path: SBOM + SPDX license texts + upstream artifact license files."""
    comps, lic_texts_map = process_sboms(uploaded_files)
    if not comps:
        st.error("No components found across the uploaded files.")
        return ""

    merged = dedupe_merge(comps)

    appended_texts: Dict[str,str] = {}

    for c in merged:
        lic_expr = c.get("license") or ""
        ids = split_license_expression(lic_expr)

        # 1) Append embedded SPDX texts from SBOM if requested
        if include_spdx_texts and lic_texts_map:
            for lid in ids:
                if lid in lic_texts_map and lid not in appended_texts:
                    appended_texts[lid] = lic_texts_map[lid]

        # 2) Fetch canonical SPDX texts for IDs
        if include_spdx_texts:
            for lid in ids:
                if lid not in appended_texts:
                    txt = fetch_spdx_text(lid)
                    if txt:
                        appended_texts[lid] = txt

        # 3) Fetch upstream license/notice files via ecosystem (npm/PyPI/Maven/NuGet/RubyGems/Golang) or GitHub
        fetched = fetch_license_texts_by_purl(c.get("purl"), c.get("name"), c.get("version"), c.get("source_url"))
        if fetched:
            # If we only have license files (no SPDX id), mark license conservatively
            if not c.get("license"):
                c["license"] = "Custom / See NOTICE"
            license_sources = []
            for fname, content in fetched.items():
                key = f"{(c.get('name') or 'component')}:{fname}"
                if key not in appended_texts:
                    appended_texts[key] = content
                license_sources.append(fname)
                # Derive copyright lines if missing
                if not c.get("copyright"):
                    cp = extract_copyright_lines(content)
                    if cp:
                        c["copyright"] = cp
            prov = c.setdefault("provenance", {})
            if license_sources:
                prov["license_sources"] = sorted(set(license_sources))
                if c.get("copyright"):
                    prov["copyright_source"] = "derived from fetched license/notice files"

    return render_md(merged, title, appended_texts)

# ------------------------ Actions -------------------------------

if go_offline:
    st.info("Generating NOTICE (offline)…")
    notice_md = generate_notice_offline(uploaded_files, output_title, include_spdx_texts)
    if notice_md:
        st.success("NOTICE generated (offline).")
        st.code(notice_md[:4000] + ("\n...\n" if len(notice_md)>4000 else ""), language="markdown")
        st.download_button("⬇️ Download NOTICE.md", notice_md.encode("utf-8"), file_name="NOTICE.md", mime="text/markdown")

if go_online:
    st.info("Generating NOTICE (online)…")
    notice_md = generate_notice_online(uploaded_files, output_title, include_spdx_texts)
    if notice_md:
        st.success("NOTICE generated (online).")
        st.code(notice_md[:4000] + ("\n...\n" if len(notice_md)>4000 else ""), language="markdown")
        st.download_button("⬇️ Download NOTICE.md", notice_md.encode("utf-8"), file_name="NOTICE.md", mime="text/markdown")

# ------------------------ Footnotes ------------------------------

st.divider()
st.markdown(
    "### References\n"
    "- SPDX License List / Tools: canonical license texts & tools ecosystem — https://spdx.dev/use/spdx-tools/\n\n"
    "- Package URL (PURL) specification — https://github.com/package-url/purl-spec\n\n"
    "- npm registry metadata (dist.tarball) — https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md\n\n"
    "- PyPI JSON API (release file URLs) — https://docs.pypi.org/api/json/\n\n"
    "- Maven Central publishing requirements (sources/javadocs) — https://central.sonatype.org/publish/requirements/\n\n"
    "- NuGet v3 flat container (nupkg download) — https://learn.microsoft.com/nuget/api/package-base-address-resource\n\n"
    "- RubyGems downloads — https://guides.rubygems.org/rubygems-org-api/\n\n"
    "- Go module proxy — https://go.dev/ref/mod#module-proxy\n"
