import os
import logging
import json
from datetime import datetime
from pathlib import Path
from django.utils.timezone import make_aware
from django.shortcuts import get_object_or_404

from core.models import LogRecord

# EVTX parsing
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

# PCAP parsing
from scapy.all import rdpcap
import re

logger = logging.getLogger(__name__)

def parse_artefact_file(artefact):
    """
    Dispatcher to appropriate parser based on artefact_type.
    """
    artefact_path = artefact.file.path
    artefact_type = artefact.artefact_type
    try:
        
        print(f"[+] Parsing artefact: {artefact.name} ({artefact_type}) at {artefact_path}")

        if artefact_type == 'evtx':
            parse_evtx(artefact, artefact_path)
        elif artefact_type == 'pcap':
            parse_pcap(artefact, artefact_path)
        elif artefact_type == 'log':
            parse_log(artefact, artefact_path)
        elif artefact_type == 'configs':
            parse_configs(artefact, artefact_path)
        else:
            parse_plain_text(artefact, artefact_path)

        artefact.parsed = True
        artefact.save()

    except Exception as e:
        logger.error(f"[!] Failed to parse {artefact}: {e}", exc_info=True)
    
    if os.path.exists(artefact_path):
        try:
            os.remove(artefact_path)
            logger.info(f"[+] Deleted artefact file: {artefact_path}")
        except Exception as e:
            logger.error(f"[!] Failed to delete artefact file {artefact_path}: {e}", exc_info=True)


def parse_evtx(artefact, path):

    with Evtx(path) as log:
        for i, record in enumerate(log.records()):
            print(f"[+] Parsing EVTX record #{i + 1}: {log.records()}")
            try:
                xml_str = record.xml()
                
                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    content=xml_str
                )
            except Exception as e:
                logger.warning(f"[!] Skipping broken EVTX record #{i}: {e}")


def parse_pcap(artefact, path):

    packets = rdpcap(path)
    for i, pkt in enumerate(packets):
        try:
            summary = pkt.show(dump=True)
            LogRecord.objects.create(
                artefact=artefact,
                record_index=i + 1,
                content=summary
            )
        except Exception as e:
            logger.warning(f"[!] Failed to parse packet #{i}: {e}")


def parse_log(artefact, path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            content = str(line.strip())
                
            LogRecord.objects.create(
                artefact=artefact,
                record_index=i + 1,
                content=content
            )



def parse_configs(artefact, path):
    try:
        ext = Path(path).suffix.lower()

        if ext == ".json":
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)

            if isinstance(data, list):
                for i, item in enumerate(data):
                    LogRecord.objects.create(
                        artefact=artefact,
                        record_index=i + 1,
                        content=json.dumps(item, ensure_ascii=False, indent=2)
                    )
            elif isinstance(data, dict):
                for i, (key, value) in enumerate(data.items()):
                    LogRecord.objects.create(
                        artefact=artefact,
                        record_index=i + 1,
                        content=json.dumps({key: value}, ensure_ascii=False, indent=2)
                    )
            else:
                logger.warning(f"[!] Unexpected JSON structure in {path}")

        elif ext == ".xml":
            tree = ET.parse(path)
            root = tree.getroot()
            for i, child in enumerate(root):
                content = ET.tostring(child, encoding='unicode')
                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    content=content.strip()
                )

        else:
            logger.warning(f"[!] Unsupported config file extension: {ext} ({path})")

    except Exception as e:
        logger.exception(f"[!] Failed to parse config file {path}: {e}")


def parse_plain_text(artefact, path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            content = str(line.strip())
            if content:
                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    content=content
                )