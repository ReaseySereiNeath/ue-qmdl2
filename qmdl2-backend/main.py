"""
QMDL2 UE Log Decoder — FastAPI Backend
========================================
Decodes Qualcomm QMDL2 diagnostic logs into structured JSON.

Pipeline:
  1. Upload QMDL2 file
  2. SCAT (signalcat) converts QMDL2 → PCAP (GSMTAP format)
  3. tshark decodes PCAP → JSON with full protocol dissection
  4. Normalizer extracts UE events into unified schema
  5. Returns structured JSON to frontend

Requirements:
  pip install "fastapi[standard]" python-multipart signalcat
  apt install tshark  (Wireshark CLI — for deep protocol decode)

Run:
  fastapi dev main.py          # development
  fastapi run main.py          # production
"""

import os
import uuid
import json
import asyncio
import subprocess
import tempfile
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from enum import Enum
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ─── Load .env ────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# ─── Config ───────────────────────────────────────────────────────
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

BASE_DIR = Path(tempfile.gettempdir()) / "qmdl2-decoder"
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "output"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE_MB = 500
VALID_EXTENSIONS = {".qmdl2", ".qmdl", ".dlf", ".qdb"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("qmdl2-decoder")


# ─── Models ───────────────────────────────────────────────────────
class JobStatus(str, Enum):
    QUEUED = "queued"
    SCAT_DECODING = "scat_decoding"
    TSHARK_PARSING = "tshark_parsing"
    NORMALIZING = "normalizing"
    COMPLETE = "complete"
    ERROR = "error"


# In-memory job store (swap with Redis for production)
jobs: dict[str, dict] = {}


# ─── Lifespan ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Check dependencies on startup."""
    # Check SCAT
    scat_ok = _check_cmd("scat", "--help")
    tshark_ok = _check_cmd("tshark", "--version")

    if scat_ok:
        logger.info("✓ SCAT (signalcat) found")
    else:
        logger.warning("✗ SCAT not found — install with: pip install signalcat")

    if tshark_ok:
        logger.info("✓ tshark found")
    else:
        logger.warning("✗ tshark not found — install with: apt install tshark")

    yield

    # Cleanup temp files on shutdown
    import shutil
    if BASE_DIR.exists():
        shutil.rmtree(BASE_DIR, ignore_errors=True)


def _check_cmd(cmd: str, arg: str) -> bool:
    try:
        subprocess.run([cmd, arg], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ─── App ──────────────────────────────────────────────────────────
app = FastAPI(
    title="QMDL2 UE Log Decoder",
    description="Decode Qualcomm QMDL2 UE diagnostic logs into structured JSON",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 1: SCAT — QMDL2 → PCAP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def scat_decode(input_path: Path, pcap_path: Path) -> tuple[bool, str]:
    """
    Run SCAT to convert QMDL2 → PCAP (GSMTAP packets).

    Command:
      scat -t qc -d <input.qmdl2> -F <output.pcap>

    Args:
      -t qc     : Qualcomm chipset type
      -d <file> : Input dump file (qmdl/qmdl2/dlf)
      -F <file> : Output PCAP file
    """
    cmd = [
        "scat", "-t", "qc",
        "-d", str(input_path),
        "-F", str(pcap_path),
        "-L", "ip,nas,rrc,pdcp,rlc,mac",
        "-C",               # Combine stdout (ML1 measurements) into PCAP as OSMOCORE_LOG
        "--events",         # Decode Qualcomm diagnostic events into GSMTAP
    ]
    logger.info(f"SCAT cmd: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        if proc.returncode != 0:
            logger.error(f"SCAT failed (rc={proc.returncode}): {stderr_str}")
            return False, f"SCAT exit code {proc.returncode}: {stderr_str[:500]}"

        if not pcap_path.exists() or pcap_path.stat().st_size == 0:
            return False, "SCAT produced empty or no PCAP output"

        size_kb = pcap_path.stat().st_size / 1024
        logger.info(f"SCAT output: {pcap_path.name} ({size_kb:.1f} KB)")

        # Log SCAT console output (cell info, warnings, etc.)
        if stdout_str.strip():
            logger.info(f"SCAT stdout:\n{stdout_str[:2000]}")

        return True, stdout_str

    except asyncio.TimeoutError:
        return False, "SCAT timed out after 300s"
    except FileNotFoundError:
        return False, "SCAT not installed. Run: pip install signalcat"
    except Exception as e:
        return False, f"SCAT exception: {str(e)}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 2: tshark — PCAP → Decoded JSON
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def tshark_decode(pcap_path: Path, json_path: Path, nas_keys: Optional[dict] = None) -> tuple[bool, str]:
    """
    Run tshark to deeply decode GSMTAP PCAP into JSON.

    tshark decodes:
    - NAS-5GS: Registration, Authentication, Security Mode, PDU Session, etc.
    - NR-RRC: RRC Setup, Reconfiguration, Measurement Report, Handover
    - LTE-RRC/NAS: Fallback 4G signaling
    - MAC/PHY: RACH, grants, scheduling

    If nas_keys is provided with encryption/integrity keys, tshark will
    attempt to decrypt NAS messages using those keys.

    Command:
      tshark -r <input.pcap> -T json -J "gsmtap lte-rrc lte-nas nr-rrc nas-5gs"
    """
    cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-T", "json",          # Output as JSON
        "-l",                  # Flush after each packet
        "--no-duplicate-keys", # Avoid duplicate key issues
    ]

    # Add NAS decryption preferences if keys are provided
    prefs_path = None
    if nas_keys:
        prefs_path = pcap_path.with_suffix(".prefs")
        prefs_lines = []

        # 5G NAS decryption
        enc_key = nas_keys.get("nas_enc_key", "")
        int_key = nas_keys.get("nas_int_key", "")
        enc_algo = nas_keys.get("nas_enc_algo", "")
        int_algo = nas_keys.get("nas_int_algo", "")

        if enc_key:
            # Enable NAS-5GS decryption with provided keys
            prefs_lines.append(f"nas-5gs.null_decipher: FALSE")
            prefs_lines.append(f"nas-5gs.decipher_key: {enc_key}")
            if enc_algo:
                prefs_lines.append(f"nas-5gs.decipher_algo: {enc_algo}")
            logger.info(f"NAS-5GS decryption enabled (enc_algo={enc_algo or 'default'})")

        if int_key:
            prefs_lines.append(f"nas-5gs.integrity_key: {int_key}")
            if int_algo:
                prefs_lines.append(f"nas-5gs.integrity_algo: {int_algo}")
            logger.info(f"NAS-5GS integrity check enabled (int_algo={int_algo or 'default'})")

        # LTE NAS decryption (same keys often apply)
        lte_enc_key = nas_keys.get("lte_nas_enc_key", enc_key)
        lte_int_key = nas_keys.get("lte_nas_int_key", int_key)
        if lte_enc_key:
            prefs_lines.append(f"nas-eps.decipher_key: {lte_enc_key}")
            prefs_lines.append(f"nas-eps.null_decipher: FALSE")
        if lte_int_key:
            prefs_lines.append(f"nas-eps.integrity_key: {lte_int_key}")

        if prefs_lines:
            for pref in prefs_lines:
                key, val = pref.split(": ", 1)
                cmd.extend(["-o", f"{key}:{val}"])
            logger.info(f"tshark NAS decryption: {len(prefs_lines)} preferences applied")
    logger.info(f"tshark cmd: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        stdout_str = stdout.decode(errors="replace")
        stderr_str = stderr.decode(errors="replace")

        if stderr_str.strip():
            # tshark warnings are common (unknown protocol versions, etc.)
            logger.debug(f"tshark stderr: {stderr_str[:1000]}")

        # Write raw JSON output
        json_path.write_text(stdout_str)

        # Validate JSON
        try:
            packets = json.loads(stdout_str)
            count = len(packets) if isinstance(packets, list) else 0
            logger.info(f"tshark decoded {count} packets")
            return True, f"{count} packets decoded"
        except json.JSONDecodeError:
            # tshark sometimes produces partial JSON — try to salvage
            logger.warning("tshark JSON parse error — attempting repair")
            if stdout_str.strip():
                json_path.write_text(stdout_str)
                return True, "Partial decode (JSON repair needed)"
            return False, "tshark produced invalid JSON"

    except asyncio.TimeoutError:
        return False, "tshark timed out after 300s"
    except FileNotFoundError:
        return False, "tshark not installed. Run: apt install tshark"
    except Exception as e:
        return False, f"tshark exception: {str(e)}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 3: Normalize tshark JSON → Unified Log Schema
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def normalize_tshark_json(json_path: Path) -> list[dict]:
    """
    Transform tshark's verbose JSON into our unified log schema.

    tshark JSON structure (per packet):
    {
      "_source": {
        "layers": {
          "frame": { "frame.time": "...", "frame.number": "...", ... },
          "udp": { ... },
          "gsmtap": { "gsmtap.type": "...", "gsmtap.sub_type": "...", ... },
          "lte-rrc": { ... },    // if LTE RRC message
          "nas-5gs": { ... },    // if 5G NAS message
          "nr-rrc": { ... },     // if NR RRC message
          ...
        }
      }
    }
    """
    try:
        raw = json.loads(json_path.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        logger.error("Failed to read tshark JSON")
        return []

    if not isinstance(raw, list):
        return []

    logs = []
    for idx, pkt in enumerate(raw):
        try:
            entry = _normalize_packet(pkt, idx)
            if entry:
                logs.append(entry)
        except Exception as e:
            logger.debug(f"Packet {idx} normalize error: {e}")

    logger.info(f"Normalized {len(logs)} log entries from {len(raw)} packets")
    return logs


def _normalize_packet(pkt: dict, idx: int) -> Optional[dict]:
    """Normalize a single tshark JSON packet into unified schema."""
    layers = pkt.get("_source", {}).get("layers", {})
    if not layers:
        return None

    # ── Frame info ──
    frame = layers.get("frame", {})
    timestamp = _extract(frame, "frame.time_epoch", "0")
    frame_num = _extract(frame, "frame.number", str(idx))

    ts_float = float(timestamp)
    ts_iso = datetime.utcfromtimestamp(ts_float).isoformat() + "Z"

    # ── GSMTAP header ──
    gsmtap = layers.get("gsmtap", {})
    gsmtap_type = _extract(gsmtap, "gsmtap.type", "0")
    gsmtap_sub_type = _extract(gsmtap, "gsmtap.sub_type", "0")
    arfcn = _extract(gsmtap, "gsmtap.arfcn", "0")

    # ── Determine protocol & decode ──
    protocol, event_type, severity, message, details = _classify_layers(layers, gsmtap_type)

    # Keep all packets — even unclassified ones provide useful timing/metadata

    # ── Build raw hex ──
    frame_raw = _extract(frame, "frame.cap_len", "0")

    return {
        "id": f"log-{str(idx).zfill(6)}",
        "timestamp": ts_iso,
        "timestampMs": ts_float * 1000,
        "protocol": protocol,
        "eventType": event_type,
        "severity": severity,
        "message": message,
        "details": details,
        "metadata": {
            "frameNumber": int(frame_num),
            "arfcn": int(arfcn),
            "gsmtapType": gsmtap_type,
            "gsmtapSubType": gsmtap_sub_type,
        },
    }


def _classify_layers(layers: dict, gsmtap_type: str) -> tuple[str, str, str, str, dict]:
    """
    Classify packet by inspecting decoded protocol layers.
    Returns: (protocol, eventType, severity, message, details)
    """
    protocol = "Unknown"
    event_type = "Unknown"
    severity = "info"
    message = ""
    details = {}

    # ── NAS 5GS ──
    nas5gs = layers.get("nas-5gs", {})
    if nas5gs:
        protocol = "NAS-5GS"
        event_type, severity, message, details = _parse_nas5gs(nas5gs)
        return protocol, event_type, severity, message, details

    # ── NR RRC ──
    nrrrc = layers.get("nr-rrc", {})
    if nrrrc:
        protocol = "NR-RRC"
        event_type, severity, message, details = _parse_nr_rrc(nrrrc)
        return protocol, event_type, severity, message, details

    # ── LTE RRC ──
    lterrc = layers.get("lte-rrc", {})
    if lterrc:
        protocol = "LTE-RRC"
        event_type, severity, message, details = _parse_lte_rrc(lterrc)
        return protocol, event_type, severity, message, details

    # ── LTE NAS ──
    ltenas = layers.get("nas-eps", {})
    if ltenas:
        protocol = "LTE-NAS"
        event_type, severity, message, details = _parse_lte_nas(ltenas)
        return protocol, event_type, severity, message, details

    # ── LTE MAC ──
    ltemac = layers.get("mac-lte", {})
    if ltemac:
        protocol = "LTE-MAC"
        event_type, severity, message, details = _parse_mac(ltemac, "LTE")
        return protocol, event_type, severity, message, details

    # ── NR MAC ──
    nrmac = layers.get("mac-nr", {})
    if nrmac:
        protocol = "NR-MAC"
        event_type, severity, message, details = _parse_mac(nrmac, "NR")
        return protocol, event_type, severity, message, details

    # ── NR PDCP ──
    nrpdcp = layers.get("pdcp-nr", {})
    if nrpdcp:
        protocol = "NR-PDCP"
        event_type = "NR-PDCP Message"
        details = _extract_layer_fields(nrpdcp, "pdcp-nr")
        message = event_type
        return protocol, event_type, severity, message, details

    # ── LTE PDCP ──
    ltepdcp = layers.get("pdcp-lte", {})
    if ltepdcp:
        protocol = "LTE-PDCP"
        event_type = "LTE-PDCP Message"
        details = _extract_layer_fields(ltepdcp, "pdcp-lte")
        message = event_type
        return protocol, event_type, severity, message, details

    # ── NR RLC ──
    nrrlc = layers.get("rlc-nr", {})
    if nrrlc:
        protocol = "NR-RLC"
        event_type = "NR-RLC Message"
        details = _extract_layer_fields(nrrlc, "rlc-nr")
        message = event_type
        return protocol, event_type, severity, message, details

    # ── LTE RLC ──
    lterlc = layers.get("rlc-lte", {})
    if lterlc:
        protocol = "LTE-RLC"
        event_type = "LTE-RLC Message"
        details = _extract_layer_fields(lterlc, "rlc-lte")
        message = event_type
        return protocol, event_type, severity, message, details

    # ── OSMOCORE_LOG (SCAT combined stdout — ML1 measurements, cell info) ──
    osmo_log = layers.get("gsmtap_log", {}) or layers.get("gsmtap.log", {})
    if not osmo_log:
        # tshark may nest it differently
        for key in layers:
            if "log" in key.lower() and "osmo" in key.lower():
                osmo_log = layers[key]
                break
    if osmo_log:
        protocol, event_type, severity, message, details = _parse_osmocore_log(layers)
        if protocol != "Unknown":
            return protocol, event_type, severity, message, details

    # ── Fallback: capture any remaining layer info ──
    gsmtap_type_map = {
        "13": "LTE-RRC", "14": "LTE-NAS", "15": "LTE-MAC",
        "18": "NR-RRC", "19": "NAS-5GS", "20": "NR-MAC",
    }
    protocol = gsmtap_type_map.get(gsmtap_type, f"GSMTAP-{gsmtap_type}")
    event_type = f"{protocol} Message"

    # Try to extract whatever fields exist in unknown layers
    known_layers = {"frame", "udp", "ip", "eth", "gsmtap", "data"}
    for layer_name, layer_data in layers.items():
        if layer_name not in known_layers and isinstance(layer_data, dict):
            details = _extract_layer_fields(layer_data, layer_name)
            if details:
                protocol = layer_name.upper()
                event_type = f"{protocol} Message"
                break

    message = event_type
    return protocol, event_type, severity, message, details


# ── NAS 5GS Parser ──

NAS5GS_MSG_TYPES = {
    "65": ("Registration Request", "info"),
    "66": ("Registration Accept", "info"),
    "67": ("Registration Complete", "info"),
    "68": ("Registration Reject", "error"),
    "69": ("Deregistration Request (UE)", "warning"),
    "70": ("Deregistration Accept (UE)", "info"),
    "71": ("Deregistration Request (NW)", "warning"),
    "72": ("Deregistration Accept (NW)", "info"),
    "86": ("Authentication Request", "info"),
    "87": ("Authentication Response", "info"),
    "88": ("Authentication Reject", "error"),
    "89": ("Authentication Failure", "error"),
    "90": ("Authentication Result", "info"),
    "93": ("Security Mode Command", "info"),
    "94": ("Security Mode Complete", "info"),
    "95": ("Security Mode Reject", "error"),
    "100": ("5GMM Status", "warning"),
    "104": ("Notification", "info"),
    "105": ("Notification Response", "info"),
    "193": ("PDU Session Establishment Request", "info"),
    "194": ("PDU Session Establishment Accept", "info"),
    "195": ("PDU Session Establishment Reject", "error"),
    "197": ("PDU Session Modification Request", "info"),
    "198": ("PDU Session Modification Accept", "info"),
    "199": ("PDU Session Modification Reject", "error"),
    "201": ("PDU Session Release Request", "warning"),
    "202": ("PDU Session Release Reject", "error"),
    "203": ("PDU Session Release Command", "warning"),
    "204": ("PDU Session Release Complete", "info"),
    "209": ("5GSM Status", "warning"),
    "84": ("Identity Request", "info"),
    "85": ("Identity Response", "info"),
    "92": ("Service Request", "info"),
    "96": ("Service Accept", "info"),
    "97": ("Service Reject", "error"),
    "76": ("Configuration Update Command", "info"),
    "77": ("Configuration Update Complete", "info"),
}


def _parse_nas5gs(layer: dict) -> tuple[str, str, str, dict]:
    """Parse NAS 5GS layer from tshark."""
    # Try to find message type
    msg_type = _find_deep(layer, "nas_5gs.mm.message_type") or \
               _find_deep(layer, "nas_5gs.sm.message_type") or \
               _find_deep(layer, "nas_5gs.common.message_type")

    if msg_type:
        # tshark gives hex string like "0x41" or decimal
        msg_type_dec = str(int(msg_type, 16)) if msg_type.startswith("0x") else msg_type

        if msg_type_dec in NAS5GS_MSG_TYPES:
            event_type, severity = NAS5GS_MSG_TYPES[msg_type_dec]
        else:
            event_type = f"NAS-5GS Message (type={msg_type})"
            severity = "info"
    else:
        event_type = "NAS-5GS Message"
        severity = "info"

    # Extract important fields
    details = {}

    # 5G-GUTI / SUPI / IMSI
    supi = _find_deep(layer, "nas_5gs.mm.supi")
    if supi:
        details["supi"] = supi

    imsi = _find_deep(layer, "nas_5gs.mm.imsi")
    if imsi:
        details["imsi"] = imsi

    # Reject cause
    cause = _find_deep(layer, "nas_5gs.mm.5gmm_cause") or \
            _find_deep(layer, "nas_5gs.sm.5gsm_cause")
    if cause:
        details["cause"] = cause
        severity = "error"

    # PLMN (MCC/MNC)
    mcc = _find_deep(layer, "e212.mcc")
    mnc = _find_deep(layer, "e212.mnc")
    if mcc and mnc:
        details["plmn"] = f"{mcc}/{mnc}"

    # Ciphering / integrity algorithms
    cipher = _find_deep(layer, "nas_5gs.mm.nas_sec_algo_enc")
    integ = _find_deep(layer, "nas_5gs.mm.nas_sec_algo_ip")
    if cipher:
        details["ciphering"] = cipher
    if integ:
        details["integrity"] = integ

    # DNN (APN)
    dnn = _find_deep(layer, "nas_5gs.sm.dnn")
    if dnn:
        details["dnn"] = dnn

    # SST / SD (Network Slice)
    sst = _find_deep(layer, "nas_5gs.mm.sst")
    if sst:
        details["nssai_sst"] = sst

    message = event_type
    if cause:
        message = f"{event_type} — Cause: {cause}"
    elif dnn:
        message = f"{event_type} — DNN: {dnn}"

    return event_type, severity, message, details


# ── NR RRC Parser ──

def _parse_nr_rrc(layer: dict) -> tuple[str, str, str, dict]:
    """Parse NR RRC layer."""
    details = {}

    # Detect message type by searching known fields
    rrc_msg_map = [
        ("nr-rrc.rrcSetupRequest_element", "RRC Setup Request", "info"),
        ("nr-rrc.rrcSetup_element", "RRC Setup", "info"),
        ("nr-rrc.rrcSetupComplete_element", "RRC Setup Complete", "info"),
        ("nr-rrc.rrcReject_element", "RRC Reject", "error"),
        ("nr-rrc.rrcReconfiguration_element", "RRC Reconfiguration", "info"),
        ("nr-rrc.rrcReconfigurationComplete_element", "RRC Reconfiguration Complete", "info"),
        ("nr-rrc.rrcRelease_element", "RRC Release", "warning"),
        ("nr-rrc.rrcReestablishmentRequest_element", "RRC Reestablishment Request", "warning"),
        ("nr-rrc.rrcReestablishment_element", "RRC Reestablishment", "warning"),
        ("nr-rrc.rrcReestablishmentComplete_element", "RRC Reestablishment Complete", "info"),
        ("nr-rrc.rrcReestablishmentReject_element", "RRC Reestablishment Reject", "error"),
        ("nr-rrc.securityModeCommand_element", "Security Mode Command", "info"),
        ("nr-rrc.securityModeComplete_element", "Security Mode Complete", "info"),
        ("nr-rrc.securityModeFailure_element", "Security Mode Failure", "error"),
        ("nr-rrc.measurementReport_element", "Measurement Report", "info"),
        ("nr-rrc.ueCapabilityInformation_element", "UE Capability Information", "info"),
        ("nr-rrc.ueCapabilityEnquiry_element", "UE Capability Enquiry", "info"),
        ("nr-rrc.systemInformationBlockType1_element", "SIB1", "info"),
        ("nr-rrc.systemInformation_element", "System Information", "info"),
        ("nr-rrc.mobilityFromNRCommand_element", "Mobility From NR", "warning"),
    ]

    event_type = "NR-RRC Message"
    severity = "info"

    for field, name, sev in rrc_msg_map:
        if _find_deep(layer, field) is not None:
            event_type = name
            severity = sev
            break

    # Extract cell info
    pci = _find_deep(layer, "nr-rrc.physCellId")
    if pci:
        details["pci"] = pci

    arfcn = _find_deep(layer, "nr-rrc.absoluteFrequencySSB")
    if arfcn:
        details["ssbArfcn"] = arfcn

    # Measurement results
    rsrp = _find_deep(layer, "nr-rrc.rsrp_Result")
    rsrq = _find_deep(layer, "nr-rrc.rsrq_Result")
    sinr = _find_deep(layer, "nr-rrc.sinr_Result")
    if rsrp:
        details["rsrp"] = rsrp
    if rsrq:
        details["rsrq"] = rsrq
    if sinr:
        details["sinr"] = sinr

    message = event_type
    if pci:
        message = f"{event_type} — PCI: {pci}"
    if rsrp:
        message = f"{event_type} — PCI: {pci or '?'}, RSRP: {rsrp}"

    return event_type, severity, message, details


# ── LTE RRC Parser ──

def _parse_lte_rrc(layer: dict) -> tuple[str, str, str, dict]:
    """Parse LTE RRC layer."""
    details = {}

    rrc_msg_map = [
        ("lte-rrc.rrcConnectionSetupComplete_element", "RRC Connection Setup Complete", "info"),
        ("lte-rrc.rrcConnectionSetup_element", "RRC Connection Setup", "info"),
        ("lte-rrc.rrcConnectionRequest_element", "RRC Connection Request", "info"),
        ("lte-rrc.rrcConnectionReconfiguration_element", "RRC Connection Reconfiguration", "info"),
        ("lte-rrc.rrcConnectionReconfigurationComplete_element", "RRC Connection Reconfig Complete", "info"),
        ("lte-rrc.rrcConnectionRelease_element", "RRC Connection Release", "warning"),
        ("lte-rrc.rrcConnectionReestablishmentRequest_element", "RRC Reestablishment Request", "warning"),
        ("lte-rrc.rrcConnectionReestablishment_element", "RRC Reestablishment", "warning"),
        ("lte-rrc.rrcConnectionReestablishmentReject_element", "RRC Reestablishment Reject", "error"),
        ("lte-rrc.measurementReport_element", "Measurement Report", "info"),
        ("lte-rrc.ueCapabilityInformation_element", "UE Capability Information", "info"),
        ("lte-rrc.systemInformationBlockType1_element", "SIB1", "info"),
        ("lte-rrc.systemInformation_element", "System Information", "info"),
        ("lte-rrc.mobilityFromEUTRACommand_element", "Handover from LTE", "warning"),
    ]

    event_type = "LTE-RRC Message"
    severity = "info"

    for field, name, sev in rrc_msg_map:
        if _find_deep(layer, field) is not None:
            event_type = name
            severity = sev
            break

    pci = _find_deep(layer, "lte-rrc.physCellId")
    earfcn = _find_deep(layer, "lte-rrc.dl_CarrierFreq")
    if pci:
        details["pci"] = pci
    if earfcn:
        details["earfcn"] = earfcn

    message = event_type
    if pci:
        message = f"{event_type} — PCI: {pci}"

    return event_type, severity, message, details


# ── LTE NAS Parser ──

LTE_NAS_MSG_TYPES = {
    "65": ("Attach Request", "info"),
    "66": ("Attach Accept", "info"),
    "67": ("Attach Complete", "info"),
    "68": ("Attach Reject", "error"),
    "69": ("Detach Request", "warning"),
    "70": ("Detach Accept", "info"),
    "72": ("TAU Request", "info"),
    "73": ("TAU Accept", "info"),
    "74": ("TAU Complete", "info"),
    "75": ("TAU Reject", "error"),
    "82": ("Authentication Request", "info"),
    "83": ("Authentication Response", "info"),
    "84": ("Authentication Reject", "error"),
    "85": ("Authentication Failure", "error"),
    "93": ("Security Mode Command", "info"),
    "94": ("Security Mode Complete", "info"),
    "95": ("Security Mode Reject", "error"),
    "193": ("Activate Default EPS Bearer", "info"),
    "197": ("Activate Dedicated EPS Bearer", "info"),
    "201": ("Deactivate EPS Bearer", "warning"),
    "205": ("PDN Connectivity Request", "info"),
    "209": ("PDN Disconnect Request", "warning"),
}


def _parse_lte_nas(layer: dict) -> tuple[str, str, str, dict]:
    """Parse LTE NAS (EPS) layer."""
    details = {}

    msg_type = _find_deep(layer, "nas_eps.nas_msg_emm_type") or \
               _find_deep(layer, "nas_eps.nas_msg_esm_type")

    event_type = "LTE-NAS Message"
    severity = "info"

    if msg_type:
        msg_dec = str(int(msg_type, 16)) if msg_type.startswith("0x") else msg_type
        if msg_dec in LTE_NAS_MSG_TYPES:
            event_type, severity = LTE_NAS_MSG_TYPES[msg_dec]
        else:
            event_type = f"LTE-NAS (type={msg_type})"

    cause = _find_deep(layer, "nas_eps.emm.cause") or \
            _find_deep(layer, "nas_eps.esm.cause")
    if cause:
        details["cause"] = cause
        severity = "error"

    imsi = _find_deep(layer, "e212.imsi")
    if imsi:
        details["imsi"] = imsi

    message = event_type
    if cause:
        message = f"{event_type} — Cause: {cause}"

    return event_type, severity, message, details


# ── MAC Parser ──

def _parse_mac(layer: dict, tech: str) -> tuple[str, str, str, dict]:
    """Parse MAC layer (LTE or NR)."""
    details = {}
    event_type = f"{tech}-MAC Message"
    severity = "info"

    # Try both LTE and NR MAC field prefixes
    prefix = f"mac-{tech.lower()}" if tech == "NR" else "mac-lte"
    rnti = _find_deep(layer, f"{prefix}.rnti") or _find_deep(layer, "mac-lte.rnti")
    rnti_type = _find_deep(layer, f"{prefix}.rnti-type") or _find_deep(layer, "mac-lte.rnti-type")
    if rnti:
        details["rnti"] = rnti
    if rnti_type:
        details["rntiType"] = rnti_type

    # Detect RACH
    if _find_deep(layer, f"{prefix}.rar") or _find_deep(layer, "mac-lte.rar") or rnti_type == "2":
        event_type = "RACH Response"
    elif rnti_type == "1":
        event_type = "RA-RNTI"

    # BSR (Buffer Status Report)
    bsr = _find_deep(layer, f"{prefix}.bsr")
    if bsr:
        event_type = f"{tech}-MAC BSR"
        details["bsr"] = bsr

    message = event_type
    return event_type, severity, message, details


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 5: Diagnostic Analysis Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Severity levels for diagnosed issues
DIAG_CRITICAL = "critical"
DIAG_WARNING = "warning"
DIAG_INFO = "info"


def diagnose_logs(logs: list[dict], metadata: dict | None = None) -> dict:
    """
    Run all diagnostic analyzers on the decoded log entries.
    Returns a structured diagnosis report with detected problems.
    """
    issues = []
    issues.extend(_diag_registration_failures(logs))
    issues.extend(_diag_auth_failures(logs))
    issues.extend(_diag_rrc_problems(logs))
    issues.extend(_diag_handover_issues(logs))
    issues.extend(_diag_rf_conditions(logs))
    issues.extend(_diag_ml1_rf_conditions(logs, metadata or {}))
    issues.extend(_diag_pdu_session_failures(logs))
    issues.extend(_diag_abnormal_patterns(logs))
    issues.extend(_diag_lte_attach_failures(logs))

    # Sort by severity (critical first), then by timestamp
    severity_order = {DIAG_CRITICAL: 0, DIAG_WARNING: 1, DIAG_INFO: 2}
    issues.sort(key=lambda x: (severity_order.get(x["severity"], 3), x.get("firstSeen", "")))

    # Build summary counts
    category_counts = {}
    severity_counts = {DIAG_CRITICAL: 0, DIAG_WARNING: 0, DIAG_INFO: 0}
    for issue in issues:
        cat = issue["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1
        severity_counts[issue["severity"]] = severity_counts.get(issue["severity"], 0) + 1

    # Overall health score (0-100)
    health_score = _compute_health_score(issues, logs)

    return {
        "healthScore": health_score,
        "totalIssues": len(issues),
        "severityCounts": severity_counts,
        "categoryCounts": category_counts,
        "issues": issues,
    }


def _compute_health_score(issues: list[dict], logs: list[dict]) -> int:
    """Compute a 0-100 health score based on detected issues."""
    if not logs:
        return 0
    score = 100
    for issue in issues:
        if issue["severity"] == DIAG_CRITICAL:
            score -= 20
        elif issue["severity"] == DIAG_WARNING:
            score -= 8
        else:
            score -= 2
    return max(0, min(100, score))


# ── Analyzer: Registration / Attach Failures ──

def _diag_registration_failures(logs: list[dict]) -> list[dict]:
    """Detect 5G registration rejects, repeated registration attempts."""
    issues = []
    reg_requests = []
    reg_rejects = []
    reg_accepts = []

    for log in logs:
        evt = log.get("eventType", "")
        if evt == "Registration Request":
            reg_requests.append(log)
        elif evt == "Registration Reject":
            reg_rejects.append(log)
        elif evt == "Registration Accept":
            reg_accepts.append(log)

    # Registration rejects
    if reg_rejects:
        causes = [r.get("details", {}).get("cause", "unknown") for r in reg_rejects]
        cause_counts = {}
        for c in causes:
            cause_counts[c] = cause_counts.get(c, 0) + 1

        issues.append({
            "id": "reg-reject",
            "category": "Registration",
            "title": "5G Registration Rejected",
            "severity": DIAG_CRITICAL,
            "description": f"{len(reg_rejects)} registration reject(s) detected. "
                           f"Cause(s): {', '.join(f'{c} ({n}x)' for c, n in cause_counts.items())}",
            "recommendation": "Check SIM provisioning, PLMN selection, and network subscription status. "
                              "Verify the UE's SUPI/IMSI is registered with the AMF.",
            "count": len(reg_rejects),
            "firstSeen": reg_rejects[0].get("timestamp", ""),
            "lastSeen": reg_rejects[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in reg_rejects],
        })

    # Repeated registration attempts (more than 3 requests without accept)
    if len(reg_requests) >= 3 and len(reg_accepts) == 0:
        issues.append({
            "id": "reg-loop",
            "category": "Registration",
            "title": "Registration Loop — No Accept Received",
            "severity": DIAG_CRITICAL,
            "description": f"{len(reg_requests)} registration requests sent but no accept received. "
                           "UE may be stuck in a registration loop.",
            "recommendation": "Check AMF logs for rejection reasons. Verify PLMN is allowed. "
                              "Check if UE is barred or in a forbidden area.",
            "count": len(reg_requests),
            "firstSeen": reg_requests[0].get("timestamp", ""),
            "lastSeen": reg_requests[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in reg_requests],
        })

    # Rapid re-registrations (more than 5 in the log)
    if len(reg_requests) > 5 and len(reg_accepts) > 0:
        issues.append({
            "id": "reg-excessive",
            "category": "Registration",
            "title": "Excessive Re-registrations",
            "severity": DIAG_WARNING,
            "description": f"{len(reg_requests)} registration requests detected ({len(reg_accepts)} accepted). "
                           "Frequent re-registrations may indicate network instability.",
            "recommendation": "Check for periodic TAU/registration timer misconfiguration. "
                              "Investigate if cell reselection is triggering re-registrations.",
            "count": len(reg_requests),
            "firstSeen": reg_requests[0].get("timestamp", ""),
            "lastSeen": reg_requests[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in reg_requests],
        })

    return issues


# ── Analyzer: Authentication Failures ──

def _diag_auth_failures(logs: list[dict]) -> list[dict]:
    """Detect authentication rejects, failures, security mode rejects."""
    issues = []
    auth_fail_events = [
        "Authentication Reject", "Authentication Failure",
        "Security Mode Reject", "Security Mode Failure",
    ]

    auth_failures = [l for l in logs if l.get("eventType") in auth_fail_events]

    if auth_failures:
        event_counts = {}
        for f in auth_failures:
            evt = f.get("eventType", "")
            event_counts[evt] = event_counts.get(evt, 0) + 1

        issues.append({
            "id": "auth-failure",
            "category": "Authentication",
            "title": "Authentication / Security Failure",
            "severity": DIAG_CRITICAL,
            "description": f"{len(auth_failures)} authentication/security failure(s): "
                           f"{', '.join(f'{e} ({n}x)' for e, n in event_counts.items())}",
            "recommendation": "Verify SIM card is properly provisioned. Check if AKA keys (K/OPc) "
                              "are synchronized between UE and network. For security mode failures, "
                              "check supported ciphering/integrity algorithms.",
            "count": len(auth_failures),
            "firstSeen": auth_failures[0].get("timestamp", ""),
            "lastSeen": auth_failures[-1].get("timestamp", ""),
            "affectedLogs": [f["id"] for f in auth_failures],
        })

    return issues


# ── Analyzer: RRC Connection Problems ──

def _diag_rrc_problems(logs: list[dict]) -> list[dict]:
    """Detect RRC setup failures, reestablishments, frequent releases."""
    issues = []

    rrc_reestablishments = [l for l in logs if "Reestablishment" in l.get("eventType", "")]
    rrc_rejects = [l for l in logs if l.get("eventType") in [
        "RRC Reject", "RRC Reestablishment Reject",
    ]]
    rrc_releases = [l for l in logs if "Release" in l.get("eventType", "") and "RRC" in l.get("protocol", "")]
    rrc_setups = [l for l in logs if "Setup" in l.get("eventType", "") and "RRC" in l.get("protocol", "")]

    # RRC reestablishments indicate radio link failures
    if rrc_reestablishments:
        issues.append({
            "id": "rrc-reestablish",
            "category": "RRC Connection",
            "title": "RRC Reestablishment Detected",
            "severity": DIAG_WARNING if len(rrc_reestablishments) < 5 else DIAG_CRITICAL,
            "description": f"{len(rrc_reestablishments)} RRC reestablishment(s) detected. "
                           "This indicates radio link failure (RLF) or handover failure.",
            "recommendation": "Check RF conditions (RSRP/RSRQ/SINR). Look for coverage gaps. "
                              "Verify handover parameters (A3 offset, time-to-trigger).",
            "count": len(rrc_reestablishments),
            "firstSeen": rrc_reestablishments[0].get("timestamp", ""),
            "lastSeen": rrc_reestablishments[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in rrc_reestablishments],
        })

    # RRC rejects
    if rrc_rejects:
        issues.append({
            "id": "rrc-reject",
            "category": "RRC Connection",
            "title": "RRC Connection Rejected",
            "severity": DIAG_CRITICAL,
            "description": f"{len(rrc_rejects)} RRC connection reject(s). "
                           "The gNB/eNB refused the UE's connection request.",
            "recommendation": "Check cell capacity and admission control settings. "
                              "Verify UE access class and barring configuration.",
            "count": len(rrc_rejects),
            "firstSeen": rrc_rejects[0].get("timestamp", ""),
            "lastSeen": rrc_rejects[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in rrc_rejects],
        })

    # Frequent RRC releases (more than 10)
    if len(rrc_releases) > 10:
        issues.append({
            "id": "rrc-frequent-release",
            "category": "RRC Connection",
            "title": "Frequent RRC Releases",
            "severity": DIAG_WARNING,
            "description": f"{len(rrc_releases)} RRC releases detected. "
                           "Frequent connection drops may indicate poor coverage or congestion.",
            "recommendation": "Check inactivity timers, T310/T311 configuration. "
                              "Review signal quality in the serving and neighbor cells.",
            "count": len(rrc_releases),
            "firstSeen": rrc_releases[0].get("timestamp", ""),
            "lastSeen": rrc_releases[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in rrc_releases[:20]],  # Limit log refs
        })

    return issues


# ── Analyzer: Handover Issues ──

def _diag_handover_issues(logs: list[dict]) -> list[dict]:
    """Detect handover failures, inter-RAT mobility issues, ping-pong."""
    issues = []

    mobility_events = [l for l in logs if l.get("eventType") in [
        "Mobility From NR", "Handover from LTE",
    ]]
    reconfigs = [l for l in logs if "Reconfiguration" in l.get("eventType", "")]

    # Inter-RAT fallbacks
    if mobility_events:
        nr_to_lte = [l for l in mobility_events if l.get("eventType") == "Mobility From NR"]
        lte_to_nr = [l for l in mobility_events if l.get("eventType") == "Handover from LTE"]

        if nr_to_lte:
            issues.append({
                "id": "handover-nr-to-lte",
                "category": "Handover",
                "title": "NR to LTE Fallback",
                "severity": DIAG_WARNING,
                "description": f"{len(nr_to_lte)} NR→LTE fallback(s) detected. "
                               "UE fell back from 5G to 4G coverage.",
                "recommendation": "Check NR coverage at fallback locations. Review B1/A2 measurement "
                                  "thresholds and inter-RAT handover parameters.",
                "count": len(nr_to_lte),
                "firstSeen": nr_to_lte[0].get("timestamp", ""),
                "lastSeen": nr_to_lte[-1].get("timestamp", ""),
                "affectedLogs": [l["id"] for l in nr_to_lte],
            })

    # Ping-pong detection: rapid alternation between reconfigs with different PCIs
    if len(reconfigs) > 6:
        # Check for rapid cell changes
        timestamps = [r.get("timestampMs", 0) for r in reconfigs]
        rapid_changes = 0
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i - 1] < 5000:  # < 5 seconds apart
                rapid_changes += 1

        if rapid_changes > 3:
            issues.append({
                "id": "handover-pingpong",
                "category": "Handover",
                "title": "Possible Handover Ping-Pong",
                "severity": DIAG_WARNING,
                "description": f"{rapid_changes} rapid reconfigurations detected within 5s intervals. "
                               "This may indicate handover ping-pong between cells.",
                "recommendation": "Review A3 offset and hysteresis parameters. Consider increasing "
                                  "time-to-trigger for handover measurements. Check CIO (Cell "
                                  "Individual Offset) between neighboring cells.",
                "count": rapid_changes,
                "firstSeen": reconfigs[0].get("timestamp", ""),
                "lastSeen": reconfigs[-1].get("timestamp", ""),
                "affectedLogs": [r["id"] for r in reconfigs[:20]],
            })

    return issues


# ── Analyzer: Poor RF Conditions ──

def _diag_rf_conditions(logs: list[dict]) -> list[dict]:
    """Detect poor RSRP/RSRQ/SINR from measurement reports."""
    issues = []

    meas_reports = [l for l in logs if l.get("eventType") == "Measurement Report"]
    poor_rsrp = []
    poor_sinr = []

    for m in meas_reports:
        details = m.get("details", {})
        rsrp_raw = details.get("rsrp", "")
        sinr_raw = details.get("sinr", "")

        # tshark RSRP values: 0-127 mapping to -140 to -44 dBm
        # Values below 40 (~-100 dBm) are poor
        if rsrp_raw:
            try:
                rsrp_val = int(rsrp_raw)
                if rsrp_val < 40:  # Poor signal
                    poor_rsrp.append(m)
            except (ValueError, TypeError):
                pass

        if sinr_raw:
            try:
                sinr_val = int(sinr_raw)
                if sinr_val < 10:  # Poor SINR
                    poor_sinr.append(m)
            except (ValueError, TypeError):
                pass

    if poor_rsrp:
        rsrp_values = []
        for m in poor_rsrp:
            r = m.get("details", {}).get("rsrp", "")
            if r:
                try:
                    rsrp_values.append(int(r))
                except ValueError:
                    pass

        worst = min(rsrp_values) if rsrp_values else "?"
        issues.append({
            "id": "rf-poor-rsrp",
            "category": "RF Quality",
            "title": "Poor Signal Strength (RSRP)",
            "severity": DIAG_WARNING if len(poor_rsrp) < 5 else DIAG_CRITICAL,
            "description": f"{len(poor_rsrp)} measurement report(s) with poor RSRP. "
                           f"Worst RSRP index: {worst} (approx. {-140 + worst} dBm). "
                           f"Out of {len(meas_reports)} total measurements.",
            "recommendation": "Check UE location relative to cell site. Verify antenna orientation, "
                              "tilt, and power settings. Consider adding small cells for coverage.",
            "count": len(poor_rsrp),
            "firstSeen": poor_rsrp[0].get("timestamp", ""),
            "lastSeen": poor_rsrp[-1].get("timestamp", ""),
            "affectedLogs": [m["id"] for m in poor_rsrp[:20]],
        })

    if poor_sinr:
        issues.append({
            "id": "rf-poor-sinr",
            "category": "RF Quality",
            "title": "Poor Signal Quality (SINR)",
            "severity": DIAG_WARNING,
            "description": f"{len(poor_sinr)} measurement report(s) with poor SINR. "
                           f"Out of {len(meas_reports)} total measurements.",
            "recommendation": "Check for interference from neighbor cells (PCI collision/confusion). "
                              "Review frequency planning and power control settings.",
            "count": len(poor_sinr),
            "firstSeen": poor_sinr[0].get("timestamp", ""),
            "lastSeen": poor_sinr[-1].get("timestamp", ""),
            "affectedLogs": [m["id"] for m in poor_sinr[:20]],
        })

    return issues


# ── Analyzer: ML1 PHY-Layer RF Conditions (Qualcomm 0xB17F / 0xB97F) ──

def _diag_ml1_rf_conditions(logs: list[dict], metadata: dict) -> list[dict]:
    """
    Analyze real PHY-layer RF from ML1 measurements.
    Sources:
      1. Normalized LTE-ML1 / NR-ML1 log entries (from OSMOCORE_LOG in PCAP via -C)
      2. SCAT console ml1Measurements / nrMeasurements (from metadata)
    """
    issues = []

    # ── Collect ML1 RSRP from decoded log entries ──
    lte_ml1_logs = [l for l in logs if l.get("protocol") == "LTE-ML1" and l.get("eventType") == "Serving Cell Measurement"]
    nr_ml1_logs = [l for l in logs if l.get("protocol") == "NR-ML1" and "Serving Cell" in l.get("eventType", "")]

    # ── Also use SCAT console parsed data (backup/supplementary) ──
    lte_console_meas = metadata.get("ml1Measurements", [])
    nr_console_meas = metadata.get("nrMeasurements", [])

    # Combine LTE RSRP values
    lte_rsrp_values = []
    for l in lte_ml1_logs:
        rsrp = l.get("details", {}).get("rsrp")
        if rsrp:
            try:
                lte_rsrp_values.append(float(rsrp))
            except (ValueError, TypeError):
                pass
    for m in lte_console_meas:
        if "rsrp" in m:
            lte_rsrp_values.append(m["rsrp"])

    # Combine NR RSRP values
    nr_rsrp_values = []
    for l in nr_ml1_logs:
        rsrp = l.get("details", {}).get("rsrp")
        if rsrp:
            try:
                nr_rsrp_values.append(float(rsrp))
            except (ValueError, TypeError):
                pass
    for m in nr_console_meas:
        if "rsrp" in m and m["rsrp"] is not None:
            nr_rsrp_values.append(m["rsrp"])

    # ── LTE RSRP Analysis ──
    if lte_rsrp_values:
        poor_lte = [r for r in lte_rsrp_values if r < -100]
        worst_lte = min(lte_rsrp_values)
        avg_lte = sum(lte_rsrp_values) / len(lte_rsrp_values)

        if poor_lte:
            issues.append({
                "id": "ml1-lte-poor-rsrp",
                "category": "RF Quality",
                "title": f"LTE Poor Signal (ML1 0xB17F)",
                "severity": DIAG_CRITICAL if worst_lte < -115 else DIAG_WARNING,
                "description": (
                    f"{len(poor_lte)}/{len(lte_rsrp_values)} LTE ML1 serving cell measurements "
                    f"below -100 dBm. Worst: {worst_lte:.1f} dBm, Average: {avg_lte:.1f} dBm."
                ),
                "recommendation": (
                    "Poor LTE signal detected from Qualcomm ML1 PHY-layer measurements. "
                    "Check UE distance to cell, antenna tilt, and consider handover to a stronger cell. "
                    "If RSRP < -115 dBm, the UE is at cell edge — expect throughput degradation."
                ),
                "count": len(poor_lte),
                "firstSeen": lte_ml1_logs[0].get("timestamp", "") if lte_ml1_logs else "",
                "lastSeen": lte_ml1_logs[-1].get("timestamp", "") if lte_ml1_logs else "",
                "affectedLogs": [l["id"] for l in lte_ml1_logs if float(l.get("details", {}).get("rsrp", "0")) < -100][:20],
            })

    # ── NR RSRP Analysis ──
    if nr_rsrp_values:
        poor_nr = [r for r in nr_rsrp_values if r < -100]
        worst_nr = min(nr_rsrp_values)
        avg_nr = sum(nr_rsrp_values) / len(nr_rsrp_values)

        if poor_nr:
            issues.append({
                "id": "ml1-nr-poor-rsrp",
                "category": "RF Quality",
                "title": f"NR Poor Signal (ML1 0xB97F)",
                "severity": DIAG_CRITICAL if worst_nr < -115 else DIAG_WARNING,
                "description": (
                    f"{len(poor_nr)}/{len(nr_rsrp_values)} NR ML1 measurements below -100 dBm. "
                    f"Worst: {worst_nr:.1f} dBm, Average: {avg_nr:.1f} dBm."
                ),
                "recommendation": (
                    "Poor NR signal from Qualcomm ML1 PHY measurements. "
                    "Check 5G NR coverage, SSB beam alignment, and consider inter-RAT "
                    "fallback to LTE if NR signal is consistently weak."
                ),
                "count": len(poor_nr),
                "firstSeen": nr_ml1_logs[0].get("timestamp", "") if nr_ml1_logs else "",
                "lastSeen": nr_ml1_logs[-1].get("timestamp", "") if nr_ml1_logs else "",
                "affectedLogs": [l["id"] for l in nr_ml1_logs][:20],
            })

    # ── LTE RSRQ Analysis ──
    lte_rsrq_values = []
    for l in lte_ml1_logs:
        rsrq = l.get("details", {}).get("rsrq")
        if rsrq:
            try:
                lte_rsrq_values.append(float(rsrq))
            except (ValueError, TypeError):
                pass
    for m in lte_console_meas:
        if "rsrq" in m:
            lte_rsrq_values.append(m["rsrq"])

    if lte_rsrq_values:
        poor_rsrq = [r for r in lte_rsrq_values if r < -15]
        if poor_rsrq:
            worst_rsrq = min(lte_rsrq_values)
            issues.append({
                "id": "ml1-lte-poor-rsrq",
                "category": "RF Quality",
                "title": "LTE Poor Signal Quality (RSRQ)",
                "severity": DIAG_WARNING,
                "description": (
                    f"{len(poor_rsrq)}/{len(lte_rsrq_values)} measurements with RSRQ < -15 dB. "
                    f"Worst: {worst_rsrq:.1f} dB. Indicates high interference or congestion."
                ),
                "recommendation": (
                    "Poor RSRQ suggests interference from neighbor cells. "
                    "Check for PCI collision/confusion, review frequency reuse plan, "
                    "and check if inter-cell interference coordination (ICIC/eICIC) is enabled."
                ),
                "count": len(poor_rsrq),
                "firstSeen": lte_ml1_logs[0].get("timestamp", "") if lte_ml1_logs else "",
                "lastSeen": lte_ml1_logs[-1].get("timestamp", "") if lte_ml1_logs else "",
                "affectedLogs": [],
            })

    return issues


# ── Analyzer: PDU Session / Bearer Failures ──

def _diag_pdu_session_failures(logs: list[dict]) -> list[dict]:
    """Detect PDU session establishment/modification rejects."""
    issues = []

    pdu_fail_events = [
        "PDU Session Establishment Reject",
        "PDU Session Modification Reject",
        "PDU Session Release Command",
    ]
    bearer_fail_events = [
        "Deactivate EPS Bearer",
    ]

    pdu_failures = [l for l in logs if l.get("eventType") in pdu_fail_events]
    bearer_failures = [l for l in logs if l.get("eventType") in bearer_fail_events]

    if pdu_failures:
        causes = [f.get("details", {}).get("cause", "unknown") for f in pdu_failures]
        cause_counts = {}
        for c in causes:
            cause_counts[c] = cause_counts.get(c, 0) + 1

        issues.append({
            "id": "pdu-failure",
            "category": "Data Session",
            "title": "PDU Session Failure",
            "severity": DIAG_CRITICAL,
            "description": f"{len(pdu_failures)} PDU session failure(s). "
                           f"Cause(s): {', '.join(f'{c} ({n}x)' for c, n in cause_counts.items())}",
            "recommendation": "Check SMF/UPF logs for session rejection reasons. Verify DNN/APN "
                              "configuration, QoS policy, and subscriber profile in UDM.",
            "count": len(pdu_failures),
            "firstSeen": pdu_failures[0].get("timestamp", ""),
            "lastSeen": pdu_failures[-1].get("timestamp", ""),
            "affectedLogs": [f["id"] for f in pdu_failures],
        })

    if bearer_failures:
        issues.append({
            "id": "bearer-deactivate",
            "category": "Data Session",
            "title": "EPS Bearer Deactivation",
            "severity": DIAG_WARNING,
            "description": f"{len(bearer_failures)} EPS bearer deactivation(s) detected.",
            "recommendation": "Check if deactivation is network-initiated or UE-initiated. "
                              "Review PGW/SGW logs for bearer management events.",
            "count": len(bearer_failures),
            "firstSeen": bearer_failures[0].get("timestamp", ""),
            "lastSeen": bearer_failures[-1].get("timestamp", ""),
            "affectedLogs": [f["id"] for f in bearer_failures],
        })

    return issues


# ── Analyzer: Abnormal Patterns ──

def _diag_abnormal_patterns(logs: list[dict]) -> list[dict]:
    """Detect abnormal patterns: deregistrations, status messages, rapid events."""
    issues = []

    # Deregistration events
    deregs = [l for l in logs if "Deregistration" in l.get("eventType", "")]
    if deregs:
        nw_initiated = [d for d in deregs if "NW" in d.get("eventType", "")]
        if nw_initiated:
            issues.append({
                "id": "pattern-nw-dereg",
                "category": "Abnormal Pattern",
                "title": "Network-Initiated Deregistration",
                "severity": DIAG_CRITICAL,
                "description": f"{len(nw_initiated)} network-initiated deregistration(s). "
                               "The network forced the UE off.",
                "recommendation": "Check if the subscription expired, UE was barred, or an administrative "
                                  "action triggered the deregistration. Review AMF event logs.",
                "count": len(nw_initiated),
                "firstSeen": nw_initiated[0].get("timestamp", ""),
                "lastSeen": nw_initiated[-1].get("timestamp", ""),
                "affectedLogs": [d["id"] for d in nw_initiated],
            })

    # 5GMM/5GSM Status messages (indicate protocol errors)
    status_msgs = [l for l in logs if l.get("eventType") in ["5GMM Status", "5GSM Status"]]
    if status_msgs:
        issues.append({
            "id": "pattern-5g-status",
            "category": "Abnormal Pattern",
            "title": "5G Protocol Error Status",
            "severity": DIAG_WARNING,
            "description": f"{len(status_msgs)} 5GMM/5GSM Status message(s). "
                           "These indicate protocol-level errors between UE and network.",
            "recommendation": "Check NAS message formatting and protocol version compatibility. "
                              "Review if mandatory IEs are missing in NAS messages.",
            "count": len(status_msgs),
            "firstSeen": status_msgs[0].get("timestamp", ""),
            "lastSeen": status_msgs[-1].get("timestamp", ""),
            "affectedLogs": [s["id"] for s in status_msgs],
        })

    # Service Rejects
    svc_rejects = [l for l in logs if l.get("eventType") == "Service Reject"]
    if svc_rejects:
        issues.append({
            "id": "pattern-svc-reject",
            "category": "Abnormal Pattern",
            "title": "Service Request Rejected",
            "severity": DIAG_CRITICAL,
            "description": f"{len(svc_rejects)} service request reject(s). "
                           "The network denied UE's request to resume service.",
            "recommendation": "Check if the UE's context still exists in the AMF. "
                              "Verify if the UE needs to re-register after idle timeout.",
            "count": len(svc_rejects),
            "firstSeen": svc_rejects[0].get("timestamp", ""),
            "lastSeen": svc_rejects[-1].get("timestamp", ""),
            "affectedLogs": [s["id"] for s in svc_rejects],
        })

    return issues


# ── Analyzer: LTE Attach Failures ──

def _diag_lte_attach_failures(logs: list[dict]) -> list[dict]:
    """Detect LTE attach rejects and TAU rejects."""
    issues = []

    attach_rejects = [l for l in logs if l.get("eventType") == "Attach Reject"]
    tau_rejects = [l for l in logs if l.get("eventType") == "TAU Reject"]

    if attach_rejects:
        causes = [r.get("details", {}).get("cause", "unknown") for r in attach_rejects]
        cause_counts = {}
        for c in causes:
            cause_counts[c] = cause_counts.get(c, 0) + 1

        issues.append({
            "id": "lte-attach-reject",
            "category": "Registration",
            "title": "LTE Attach Rejected",
            "severity": DIAG_CRITICAL,
            "description": f"{len(attach_rejects)} LTE attach reject(s). "
                           f"Cause(s): {', '.join(f'{c} ({n}x)' for c, n in cause_counts.items())}",
            "recommendation": "Check SIM provisioning in HSS/UDM. Verify APN configuration "
                              "and subscriber profile. Check EMM cause codes for specifics.",
            "count": len(attach_rejects),
            "firstSeen": attach_rejects[0].get("timestamp", ""),
            "lastSeen": attach_rejects[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in attach_rejects],
        })

    if tau_rejects:
        issues.append({
            "id": "lte-tau-reject",
            "category": "Registration",
            "title": "LTE TAU Rejected",
            "severity": DIAG_WARNING,
            "description": f"{len(tau_rejects)} Tracking Area Update reject(s).",
            "recommendation": "Check if the UE's context expired in the MME. "
                              "Verify TAI list and tracking area configuration.",
            "count": len(tau_rejects),
            "firstSeen": tau_rejects[0].get("timestamp", ""),
            "lastSeen": tau_rejects[-1].get("timestamp", ""),
            "affectedLogs": [r["id"] for r in tau_rejects],
        })

    return issues


# ── OSMOCORE_LOG Parser (SCAT -C combined stdout in PCAP) ──

def _parse_osmocore_log(layers: dict) -> tuple[str, str, str, str, dict]:
    """
    Parse OSMOCORE_LOG packets which contain SCAT's ML1 measurement data
    embedded into the PCAP via the -C flag.

    These packets carry text strings like:
      "LTE SCell: EARFCN: 1850, PCI: 123, Measured RSRP: -95.50, ..."
      "NR ML1 Meas Packet: Layers: 1, ..."
      "Layer 0: NR-ARFCN: 631392, SCell PCI: 456/SSB: 2, RSRP: -88.50/-91.20"
    """
    protocol = "Unknown"
    event_type = "Unknown"
    severity = "info"
    message = ""
    details = {}

    # Try to extract the log text from data layer
    data_layer = layers.get("data", {}) or layers.get("data-text-lines", {})
    text = ""

    # The text may be in the raw data payload
    if isinstance(data_layer, dict):
        text = _find_deep(data_layer, "data.text") or ""
        if not text:
            text = _find_deep(data_layer, "data.data") or ""

    # Also check the frame data
    if not text:
        for layer_name, layer_data in layers.items():
            if isinstance(layer_data, dict):
                t = _find_deep(layer_data, "text") or _find_deep(layer_data, "data.text")
                if t and isinstance(t, str) and len(t) > 10:
                    text = t
                    break

    if not text:
        return "Unknown", "Unknown", "info", "", {}

    # ── LTE SCell Measurement (0xB17F) ──
    lte_scell = re.search(
        r"LTE\s+SCell:\s+EARFCN:\s+(\d+),\s+PCI:\s+(\d+),\s+"
        r"Measured\s+RSRP:\s+([-\d.]+).*?RSSI:\s+([-\d.]+).*?RSRQ:\s+([-\d.]+)",
        text
    )
    if lte_scell:
        protocol = "LTE-ML1"
        event_type = "Serving Cell Measurement"
        details = {
            "earfcn": lte_scell.group(1),
            "pci": lte_scell.group(2),
            "rsrp": lte_scell.group(3),
            "rssi": lte_scell.group(4),
            "rsrq": lte_scell.group(5),
        }
        rsrp = float(lte_scell.group(3))
        if rsrp < -110:
            severity = "error"
        elif rsrp < -100:
            severity = "warning"
        message = f"LTE SCell PCI {lte_scell.group(2)} — RSRP: {lte_scell.group(3)} dBm, RSRQ: {lte_scell.group(5)} dB"
        return protocol, event_type, severity, message, details

    # ── NR ML1 Layer Measurement ──
    nr_layer = re.search(
        r"Layer\s+(\d+):\s+NR-ARFCN:\s+(\d+),\s+SCell\s+PCI:\s+(\d+)/SSB:\s+(\d+),\s+RSRP:\s+([-\d./]+)",
        text
    )
    if nr_layer:
        protocol = "NR-ML1"
        event_type = "NR Serving Cell Measurement"
        rsrp_str = nr_layer.group(5)
        rsrp_values = [float(r) for r in rsrp_str.split("/") if r.strip()]
        best_rsrp = max(rsrp_values) if rsrp_values else 0
        details = {
            "nrArfcn": nr_layer.group(2),
            "pci": nr_layer.group(3),
            "ssb": nr_layer.group(4),
            "rsrp": f"{best_rsrp:.2f}",
            "rsrpPerRx": rsrp_str,
        }
        if best_rsrp < -110:
            severity = "error"
        elif best_rsrp < -100:
            severity = "warning"
        message = f"NR SCell PCI {nr_layer.group(3)} — RSRP: {rsrp_str} dBm"
        return protocol, event_type, severity, message, details

    # ── LTE ML1 Cell Info (0xB197) ──
    ml1_cell = re.search(
        r"LTE\s+ML1\s+Cell\s+Info:\s+EARFCN:\s+(\d+),\s+PCI:\s+(\d+),\s+Bandwidth:\s+(.+?),\s+Num\s+antennas:\s+(\d+)",
        text
    )
    if ml1_cell:
        protocol = "LTE-ML1"
        event_type = "ML1 Cell Info"
        details = {
            "earfcn": ml1_cell.group(1),
            "pci": ml1_cell.group(2),
            "bandwidth": ml1_cell.group(3),
            "numAntennas": ml1_cell.group(4),
        }
        message = f"LTE Cell PCI {ml1_cell.group(2)} — BW: {ml1_cell.group(3)}, Antennas: {ml1_cell.group(4)}"
        return protocol, event_type, severity, message, details

    # ── NR MIB ──
    nr_mib = re.search(
        r"NR\s+MIB:\s+NR-ARFCN:\s+(\d+),\s+PCI:\s+(\d+),\s+SFN:\s+(\d+)",
        text
    )
    if nr_mib:
        protocol = "NR-ML1"
        event_type = "NR MIB Info"
        details = {
            "nrArfcn": nr_mib.group(1),
            "pci": nr_mib.group(2),
            "sfn": nr_mib.group(3),
        }
        message = f"NR MIB PCI {nr_mib.group(2)} — ARFCN: {nr_mib.group(1)}, SFN: {nr_mib.group(3)}"
        return protocol, event_type, severity, message, details

    # ── NR Cell Measurement (neighbor) ──
    nr_cell = re.search(
        r"Cell\s+(\d+):\s+PCI:\s+(\d+).*?RSRP:\s+([-\d.]+).*?RSRQ:\s+([-\d.]+)",
        text
    )
    if nr_cell:
        protocol = "NR-ML1"
        event_type = "NR Neighbor Cell Measurement"
        rsrp = float(nr_cell.group(3))
        details = {
            "cellIndex": nr_cell.group(1),
            "pci": nr_cell.group(2),
            "rsrp": nr_cell.group(3),
            "rsrq": nr_cell.group(4),
        }
        if rsrp < -110:
            severity = "warning"
        message = f"NR NCell PCI {nr_cell.group(2)} — RSRP: {nr_cell.group(3)} dBm, RSRQ: {nr_cell.group(4)} dB"
        return protocol, event_type, severity, message, details

    # ── Generic SCAT log message ──
    if len(text) > 5:
        protocol = "SCAT-LOG"
        event_type = "SCAT Log Message"
        message = text[:200]
        details = {"text": text[:500]}
        return protocol, event_type, severity, message, details

    return protocol, event_type, severity, message, details


# ── Generic Layer Extractor ──

def _extract_layer_fields(layer: dict, prefix: str, max_fields: int = 20) -> dict:
    """Extract top-level fields from any tshark protocol layer."""
    details = {}
    count = 0
    if not isinstance(layer, dict):
        return details
    for key, val in layer.items():
        if count >= max_fields:
            break
        # Skip tree elements and internal fields
        if key.endswith("_tree") or key.endswith("_element"):
            continue
        if isinstance(val, str):
            # Use short key name (strip prefix)
            short_key = key.replace(f"{prefix}.", "") if key.startswith(f"{prefix}.") else key
            details[short_key] = val
            count += 1
        elif isinstance(val, list) and val and isinstance(val[0], str):
            short_key = key.replace(f"{prefix}.", "") if key.startswith(f"{prefix}.") else key
            details[short_key] = val[0]
            count += 1
    return details


# ── Helpers ──

def _extract(d: dict, key: str, default: str = "") -> str:
    """Extract value from tshark dict, handling nested lists."""
    val = d.get(key, default)
    if isinstance(val, list):
        return val[0] if val else default
    return str(val) if val is not None else default


def _find_deep(d, key: str, max_depth: int = 10):
    """Recursively search for a key in nested dicts/lists."""
    if max_depth <= 0:
        return None
    if isinstance(d, dict):
        if key in d:
            val = d[key]
            if isinstance(val, list):
                return val[0] if val else None
            return val
        for v in d.values():
            result = _find_deep(v, key, max_depth - 1)
            if result is not None:
                return result
    elif isinstance(d, list):
        for item in d:
            result = _find_deep(item, key, max_depth - 1)
            if result is not None:
                return result
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 4: SCAT console output parser (cell info, ML1, signal, etc.)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_scat_console(stdout: str) -> dict:
    """
    Parse SCAT's full console output which contains:

    1. Cell Info lines:
       Radio 0: LTE RRC SCell Info: EARFCN 1850, Band 3, PCI 123, MCC 440, MNC 10
       Radio 0: NR RRC SCell Info: NR-ARFCN 631392, Band n78, PCI 456

    2. ML1 Serving Cell Measurements (Qualcomm log 0xB17F):
       Radio 0: LTE SCell: EARFCN: 1850, PCI: 123, Measured RSRP: -95.50, Measured RSSI: -67.30, Measured RSRQ: -12.40

    3. ML1 Neighbor Cell Measurements (Qualcomm log 0xB180):
       Radio 0: LTE NCell: EARFCN: 1850, N: 3, ....

    4. NR ML1 Measurement Database (Qualcomm log 0xB97F):
       Radio 0: Layer 0: NR-ARFCN: 631392, SCell PCI:  456/SSB: 2, RSRP: -88.50/-91.20, ...
       Radio 0: └── Cell 0: PCI:  457, RSRP: -92.30, RSRQ: -11.40, Num Beams: 2

    5. NR MIB Info:
       Radio 0: NR MIB: NR-ARFCN: 631392, PCI:  456, SFN: 0, SCS: 30 kHz

    6. LTE ML1 Cell Info (Qualcomm log 0xB197):
       Radio 0: LTE ML1 Cell Info: EARFCN: 1850, PCI: 123, Bandwidth: 20 MHz, Num antennas: 4

    Returns dict with: cellInfo, ml1Measurements, nrMeasurements, ml1CellInfo
    """
    result = {
        "cellInfo": [],
        "ml1Measurements": [],
        "nrMeasurements": [],
        "ml1CellInfo": [],
    }

    lines = stdout.split("\n")

    # ── Pattern: Cell Info ──
    cell_pattern = re.compile(
        r"Radio\s+(\d+):\s+(LTE|NR)\s+RRC\s+SCell\s+Info:\s+(.*)"
    )
    # ── Pattern: LTE SCell Measurement (0xB17F) ──
    lte_scell_pattern = re.compile(
        r"Radio\s+(\d+):\s+LTE\s+SCell:\s+EARFCN:\s+(\d+),\s+PCI:\s+(\d+),\s+"
        r"Measured\s+RSRP:\s+([-\d.]+),\s+Measured\s+RSSI:\s+([-\d.]+),\s+"
        r"Measured\s+RSRQ:\s+([-\d.]+)"
    )
    # ── Pattern: NR ML1 Layer ──
    nr_layer_pattern = re.compile(
        r"Radio\s+(\d+):\s+Layer\s+(\d+):\s+NR-ARFCN:\s+(\d+),\s+SCell\s+PCI:\s+(\d+)/SSB:\s+(\d+),\s+RSRP:\s+([-\d./]+)"
    )
    # ── Pattern: NR/LTE Cell in ML1 ──
    nr_cell_pattern = re.compile(
        r"Radio\s+(\d+):\s+.*Cell\s+(\d+):\s+PCI:\s+(\d+).*?RSRP:\s+([-\d.]+).*?RSRQ:\s+([-\d.]+)"
    )
    # ── Pattern: NR MIB ──
    nr_mib_pattern = re.compile(
        r"Radio\s+(\d+):\s+NR\s+MIB:\s+NR-ARFCN:\s+(\d+),\s+PCI:\s+(\d+),\s+SFN:\s+(\d+)"
    )
    # ── Pattern: LTE ML1 Cell Info (0xB197) ──
    lte_ml1_cell_pattern = re.compile(
        r"Radio\s+(\d+):\s+LTE\s+ML1\s+Cell\s+Info:\s+EARFCN:\s+(\d+),\s+PCI:\s+(\d+),\s+Bandwidth:\s+(.+?),\s+Num\s+antennas:\s+(\d+)"
    )

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ── Cell Info ──
        m = cell_pattern.search(line)
        if m:
            entry = {
                "type": "cell_info",
                "radio": int(m.group(1)),
                "technology": m.group(2),
                "raw": m.group(3).strip(),
            }
            for kv in m.group(3).split(","):
                kv = kv.strip()
                if "EARFCN" in kv or "NR-ARFCN" in kv or "ARFCN" in kv:
                    entry["arfcn"] = kv.split()[-1]
                elif "Band" in kv:
                    entry["band"] = kv.replace("Band", "").strip()
                elif "PCI" in kv:
                    entry["pci"] = kv.replace("PCI", "").strip()
                elif "MCC" in kv:
                    entry["mcc"] = kv.replace("MCC", "").strip()
                elif "MNC" in kv:
                    entry["mnc"] = kv.replace("MNC", "").strip()
                elif "Bandwidth" in kv:
                    entry["bandwidth"] = kv.replace("Bandwidth", "").strip()
                elif "xTAC" in kv or "xCID" in kv:
                    parts = kv.split()
                    if len(parts) >= 2:
                        entry["tacCid"] = parts[-1]
            result["cellInfo"].append(entry)
            continue

        # ── LTE SCell Measurement (RSRP/RSSI/RSRQ from 0xB17F) ──
        m = lte_scell_pattern.search(line)
        if m:
            result["ml1Measurements"].append({
                "type": "lte_scell_meas",
                "radio": int(m.group(1)),
                "technology": "LTE",
                "earfcn": int(m.group(2)),
                "pci": int(m.group(3)),
                "rsrp": float(m.group(4)),
                "rssi": float(m.group(5)),
                "rsrq": float(m.group(6)),
            })
            continue

        # ── NR ML1 Layer Measurement ──
        m = nr_layer_pattern.search(line)
        if m:
            rsrp_str = m.group(6)
            rsrp_values = [float(r) for r in rsrp_str.split("/") if r.strip()]
            result["nrMeasurements"].append({
                "type": "nr_layer_meas",
                "radio": int(m.group(1)),
                "technology": "NR",
                "layer": int(m.group(2)),
                "nrArfcn": int(m.group(3)),
                "pci": int(m.group(4)),
                "ssb": int(m.group(5)),
                "rsrpPerRx": rsrp_values,
                "rsrp": min(rsrp_values) if rsrp_values else None,
            })
            continue

        # ── NR/LTE Cell Measurement (neighbor cells) ──
        m = nr_cell_pattern.search(line)
        if m:
            result["nrMeasurements"].append({
                "type": "nr_cell_meas",
                "radio": int(m.group(1)),
                "cellIndex": int(m.group(2)),
                "pci": int(m.group(3)),
                "rsrp": float(m.group(4)),
                "rsrq": float(m.group(5)),
            })
            continue

        # ── LTE ML1 Cell Info ──
        m = lte_ml1_cell_pattern.search(line)
        if m:
            result["ml1CellInfo"].append({
                "type": "lte_ml1_cell_info",
                "radio": int(m.group(1)),
                "earfcn": int(m.group(2)),
                "pci": int(m.group(3)),
                "bandwidth": m.group(4),
                "numAntennas": int(m.group(5)),
            })
            continue

        # ── NR MIB ──
        m = nr_mib_pattern.search(line)
        if m:
            result["ml1CellInfo"].append({
                "type": "nr_mib",
                "radio": int(m.group(1)),
                "nrArfcn": int(m.group(2)),
                "pci": int(m.group(3)),
                "sfn": int(m.group(4)),
            })
            continue

    logger.info(
        f"SCAT console parsed: {len(result['cellInfo'])} cell info, "
        f"{len(result['ml1Measurements'])} LTE ML1 meas, "
        f"{len(result['nrMeasurements'])} NR meas, "
        f"{len(result['ml1CellInfo'])} ML1 cell info"
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Background Processing Pipeline
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def process_qmdl2(job_id: str, file_path: Path, nas_keys: Optional[dict] = None):
    """Full pipeline: QMDL2 → SCAT → PCAP → tshark → JSON → Normalize."""
    pcap_path = OUTPUT_DIR / f"{job_id}.pcap"
    tshark_json_path = OUTPUT_DIR / f"{job_id}_raw.json"
    result_path = OUTPUT_DIR / f"{job_id}.json"

    try:
        # ── Step 1: SCAT ──
        jobs[job_id]["status"] = JobStatus.SCAT_DECODING
        jobs[job_id]["progress"] = 0.2

        ok, scat_output = await scat_decode(file_path, pcap_path)
        if not ok:
            jobs[job_id]["status"] = JobStatus.ERROR
            jobs[job_id]["error"] = scat_output
            return

        # Parse SCAT console output (ML1 measurements, cell info, NR beams)
        scat_data = parse_scat_console(scat_output)
        jobs[job_id]["cellInfo"] = scat_data["cellInfo"]

        # ── Step 2: tshark ──
        jobs[job_id]["status"] = JobStatus.TSHARK_PARSING
        jobs[job_id]["progress"] = 0.5

        ok, tshark_msg = await tshark_decode(pcap_path, tshark_json_path, nas_keys=nas_keys)
        if not ok:
            jobs[job_id]["status"] = JobStatus.ERROR
            jobs[job_id]["error"] = tshark_msg
            return

        # ── Step 3: Normalize ──
        jobs[job_id]["status"] = JobStatus.NORMALIZING
        jobs[job_id]["progress"] = 0.8

        logs = normalize_tshark_json(tshark_json_path)

        # Save final result with full SCAT data
        result = {
            "metadata": {
                "jobId": job_id,
                "filename": jobs[job_id]["filename"],
                "processedAt": datetime.utcnow().isoformat() + "Z",
                "totalPackets": len(logs),
                "cellInfo": scat_data["cellInfo"],
                "ml1Measurements": scat_data["ml1Measurements"],
                "nrMeasurements": scat_data["nrMeasurements"],
                "ml1CellInfo": scat_data["ml1CellInfo"],
                "pipeline": "SCAT (-C --events) → PCAP → tshark → JSON",
            },
            "logs": logs,
        }
        result_path.write_text(json.dumps(result, indent=2))

        # ── Done ──
        jobs[job_id]["status"] = JobStatus.COMPLETE
        jobs[job_id]["progress"] = 1.0
        jobs[job_id]["logCount"] = len(logs)
        logger.info(f"Job {job_id} complete: {len(logs)} UE log entries")

    except Exception as e:
        jobs[job_id]["status"] = JobStatus.ERROR
        jobs[job_id]["error"] = str(e)
        logger.error(f"Job {job_id} failed: {e}", exc_info=True)
    finally:
        # Cleanup uploaded file
        if file_path.exists():
            file_path.unlink()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# API Routes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/")
async def root():
    return {
        "service": "QMDL2 UE Log Decoder",
        "version": "0.4.0",
        "pipeline": "QMDL2 → SCAT (-C --events) → PCAP → tshark → Structured JSON",
        "protocols": [
            "NAS-5GS (Registration, Auth, PDU Session, Security, Deregistration)",
            "NR-RRC (Setup, Reconfig, Release, Measurement, Handover, SIB)",
            "LTE-RRC (Connection, Reconfig, Release, Measurement, SIB)",
            "LTE-NAS (Attach, Detach, TAU, Auth, EPS Bearer)",
            "MAC (LTE-MAC, NR-MAC — RACH, BSR, Grants)",
            "PDCP (LTE-PDCP, NR-PDCP)",
            "RLC (LTE-RLC, NR-RLC)",
            "LTE-ML1 (Serving Cell Meas 0xB17F, Cell Info 0xB197, Neighbor Meas 0xB180)",
            "NR-ML1 (Meas DB Update 0xB97F, MIB, Serving Cell, Beam Measurements)",
            "Qualcomm Events (diagnostic event reports)",
        ],
        "nasDecryption": {
            "supported": True,
            "description": "Provide 128-bit NAS keys (K_NAS_enc, K_NAS_int) during upload to decrypt ciphered NAS messages",
            "algorithms": ["nea0 (null)", "nea1 (SNOW)", "nea2 (AES)", "nea3 (ZUC)"],
            "keyFormat": "32 hex characters (128-bit)",
        },
        "diagnostics": [
            "Registration/Attach failures",
            "Authentication/Security failures",
            "RRC connection problems (RLF, reestablishment, rejects)",
            "Handover issues (inter-RAT fallback, ping-pong)",
            "RF quality analysis (ML1 RSRP/RSRQ/SINR from 0xB17F/0xB97F)",
            "PDU Session / EPS Bearer failures",
            "Abnormal patterns (deregistration, protocol errors)",
        ],
    }


@app.post("/api/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    nas_enc_key: Optional[str] = Form(None),
    nas_int_key: Optional[str] = Form(None),
    nas_enc_algo: Optional[str] = Form(None),
    nas_int_algo: Optional[str] = Form(None),
    lte_nas_enc_key: Optional[str] = Form(None),
    lte_nas_int_key: Optional[str] = Form(None),
):
    """Upload a QMDL2/QMDL/DLF file for decoding.

    Optional NAS decryption keys (128-bit hex strings):
    - nas_enc_key: 5G NAS ciphering key (K_NAS_enc), 32 hex chars
    - nas_int_key: 5G NAS integrity key (K_NAS_int), 32 hex chars
    - nas_enc_algo: Ciphering algorithm (e.g., "nea1", "nea2")
    - nas_int_algo: Integrity algorithm (e.g., "nia1", "nia2")
    - lte_nas_enc_key: LTE NAS ciphering key (overrides nas_enc_key for 4G)
    - lte_nas_int_key: LTE NAS integrity key (overrides nas_int_key for 4G)
    """
    # Validate extension
    ext = Path(file.filename or "unknown").suffix.lower()
    if ext not in VALID_EXTENSIONS:
        raise HTTPException(
            400,
            detail=f"Unsupported file type '{ext}'. Accepted: {', '.join(VALID_EXTENSIONS)}"
        )

    # Validate size
    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise HTTPException(
            400,
            detail=f"File too large ({size_mb:.1f} MB). Maximum: {MAX_FILE_SIZE_MB} MB"
        )

    # Validate NAS keys if provided (must be valid hex, 32 chars = 128 bits)
    hex_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
    nas_keys = None
    has_keys = any([nas_enc_key, nas_int_key, lte_nas_enc_key, lte_nas_int_key])

    if has_keys:
        nas_keys = {}
        for key_name, key_val in [
            ("nas_enc_key", nas_enc_key),
            ("nas_int_key", nas_int_key),
            ("lte_nas_enc_key", lte_nas_enc_key),
            ("lte_nas_int_key", lte_nas_int_key),
        ]:
            if key_val:
                key_val = key_val.strip()
                if not hex_pattern.match(key_val):
                    raise HTTPException(
                        400,
                        detail=f"Invalid {key_name}: must be exactly 32 hex characters (128-bit key)"
                    )
                nas_keys[key_name] = key_val

        if nas_enc_algo:
            nas_keys["nas_enc_algo"] = nas_enc_algo.strip()
        if nas_int_algo:
            nas_keys["nas_int_algo"] = nas_int_algo.strip()

        logger.info(f"NAS decryption keys provided: {list(nas_keys.keys())}")

    # Save file
    job_id = uuid.uuid4().hex[:8]
    file_path = UPLOAD_DIR / f"{job_id}{ext}"
    file_path.write_bytes(content)

    # Create job
    jobs[job_id] = {
        "jobId": job_id,
        "status": JobStatus.QUEUED,
        "filename": file.filename,
        "fileSizeMB": round(size_mb, 2),
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "progress": 0.0,
        "error": None,
        "logCount": 0,
        "cellInfo": [],
        "nasDecryption": bool(nas_keys),
    }

    # Start processing
    background_tasks.add_task(process_qmdl2, job_id, file_path, nas_keys)

    return JSONResponse(
        status_code=202,
        content={
            "jobId": job_id,
            "status": "queued",
            "message": f"Processing {file.filename} ({size_mb:.1f} MB)",
        },
    )


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    """Get job status and metadata."""
    if job_id not in jobs:
        raise HTTPException(404, "Job not found")
    return jobs[job_id]


@app.get("/api/logs/{job_id}")
async def get_logs(
    job_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=5000),
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """Get decoded UE log entries with filtering and pagination."""
    if job_id not in jobs:
        raise HTTPException(404, "Job not found")

    job = jobs[job_id]
    if job["status"] != JobStatus.COMPLETE:
        raise HTTPException(400, f"Job not ready. Status: {job['status']}")

    result_path = OUTPUT_DIR / f"{job_id}.json"
    if not result_path.exists():
        raise HTTPException(404, "Result file not found")

    data = json.loads(result_path.read_text())
    logs = data.get("logs", [])

    # Apply filters
    if protocol:
        logs = [l for l in logs if l.get("protocol") == protocol]
    if severity:
        logs = [l for l in logs if l.get("severity") == severity]
    if event_type:
        logs = [l for l in logs if event_type.lower() in l.get("eventType", "").lower()]
    if search:
        q = search.lower()
        logs = [l for l in logs if
            q in l.get("message", "").lower() or
            q in l.get("eventType", "").lower() or
            q in l.get("protocol", "").lower() or
            q in json.dumps(l.get("details", {})).lower()
        ]

    return {
        "metadata": data.get("metadata", {}),
        "total": len(logs),
        "offset": offset,
        "limit": limit,
        "logs": logs[offset:offset + limit],
    }


@app.get("/api/logs/{job_id}/summary")
async def get_summary(job_id: str):
    """Get a summary of decoded logs — protocol counts, error counts, cell info."""
    if job_id not in jobs:
        raise HTTPException(404, "Job not found")

    job = jobs[job_id]
    if job["status"] != JobStatus.COMPLETE:
        raise HTTPException(400, f"Job not ready. Status: {job['status']}")

    result_path = OUTPUT_DIR / f"{job_id}.json"
    data = json.loads(result_path.read_text())
    logs = data.get("logs", [])

    protocol_counts = {}
    severity_counts = {"info": 0, "warning": 0, "error": 0, "critical": 0}
    event_counts = {}

    for log in logs:
        proto = log.get("protocol", "Unknown")
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        sev = log.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        evt = log.get("eventType", "Unknown")
        event_counts[evt] = event_counts.get(evt, 0) + 1

    return {
        "jobId": job_id,
        "totalLogs": len(logs),
        "protocolCounts": protocol_counts,
        "severityCounts": severity_counts,
        "eventCounts": dict(sorted(event_counts.items(), key=lambda x: -x[1])),
        "cellInfo": data.get("metadata", {}).get("cellInfo", []),
    }


@app.get("/api/logs/{job_id}/diagnose")
async def diagnose_job(job_id: str):
    """Run diagnostic analysis on decoded logs — detect problems and anomalies."""
    if job_id not in jobs:
        raise HTTPException(404, "Job not found")

    job = jobs[job_id]
    if job["status"] != JobStatus.COMPLETE:
        raise HTTPException(400, f"Job not ready. Status: {job['status']}")

    result_path = OUTPUT_DIR / f"{job_id}.json"
    if not result_path.exists():
        raise HTTPException(404, "Result file not found")

    data = json.loads(result_path.read_text())
    logs = data.get("logs", [])

    metadata = data.get("metadata", {})
    diagnosis = diagnose_logs(logs, metadata)
    diagnosis["jobId"] = job_id
    diagnosis["filename"] = job.get("filename", "")
    diagnosis["cellInfo"] = metadata.get("cellInfo", [])
    diagnosis["ml1Measurements"] = metadata.get("ml1Measurements", [])
    diagnosis["nrMeasurements"] = metadata.get("nrMeasurements", [])
    diagnosis["ml1CellInfo"] = metadata.get("ml1CellInfo", [])

    return diagnosis


@app.get("/api/logs/{job_id}/pcap")
async def download_pcap(job_id: str):
    """Download the intermediate PCAP file for use in Wireshark."""
    pcap_path = OUTPUT_DIR / f"{job_id}.pcap"
    if not pcap_path.exists():
        raise HTTPException(404, "PCAP not found")

    from fastapi.responses import FileResponse
    return FileResponse(
        pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{job_id}.pcap",
    )


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and all associated files."""
    if job_id not in jobs:
        raise HTTPException(404, "Job not found")

    for suffix in [".pcap", "_raw.json", ".json"]:
        p = OUTPUT_DIR / f"{job_id}{suffix}"
        if p.exists():
            p.unlink()

    del jobs[job_id]
    return {"message": f"Job {job_id} deleted"}
