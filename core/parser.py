import os
import logging
import json
from datetime import datetime

from django.utils.timezone import make_aware
from django.shortcuts import get_object_or_404

from core.models import LogRecord

# EVTX parsing
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

# PCAP parsing
from scapy.all import rdpcap

logger = logging.getLogger(__name__)

def parse_artefact_file(artefact):
    """
    Dispatcher to appropriate parser based on artefact_type.
    """
    try:
        artefact_path = artefact.file.path
        artefact_type = artefact.artefact_type

        if artefact_type == 'evtx':
            parse_evtx(artefact, artefact_path)
        elif artefact_type == 'pcap':
            parse_pcap(artefact, artefact_path)
        elif artefact_type == 'sysmon':
            parse_sysmon(artefact, artefact_path)
        elif artefact_type == 'firewall':
            parse_firewall(artefact, artefact_path)
        else:
            parse_plain_text(artefact, artefact_path)

        artefact.parsed = True
        artefact.save()

    except Exception as e:
        logger.error(f"[!] Failed to parse {artefact}: {e}", exc_info=True)


def parse_evtx(artefact, path):

    with Evtx(path) as log:
        for i, record in enumerate(log.records()):
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                timestamp = root.find(".//TimeCreated").attrib.get("SystemTime", None)
                if timestamp:
                    timestamp = make_aware(datetime.fromisoformat(timestamp.replace("Z", "+00:00")))

                event_id = root.findtext(".//EventID")
                provider = root.find(".//Provider").attrib.get("Name") if root.find(".//Provider") is not None else None

                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    timestamp=timestamp,
                    content=xml_str,
                    metadata={
                        "event_id": event_id,
                        "provider": provider
                    }
                )
            except Exception as e:
                logger.warning(f"[!] Skipping broken EVTX record #{i}: {e}")


def parse_pcap(artefact, path):

    packets = rdpcap(path)
    for i, pkt in enumerate(packets):
        try:
            timestamp = make_aware(datetime.fromtimestamp(pkt.time))
            summary = pkt.summary()

            metadata = {
                "src": getattr(pkt[0], "src", ""),
                "dst": getattr(pkt[0], "dst", ""),
                "proto": pkt.name
            }

            LogRecord.objects.create(
                artefact=artefact,
                record_index=i + 1,
                timestamp=timestamp,
                content=summary,
                metadata=metadata
            )
        except Exception as e:
            logger.warning(f"[!] Failed to parse packet #{i}: {e}")


def parse_sysmon(artefact, path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            content = line.strip()
            if not content:
                continue

            try:
                parsed = json.loads(content)
                timestamp = parsed.get("UtcTime") or parsed.get("Timestamp")
                timestamp = make_aware(datetime.fromisoformat(timestamp)) if timestamp else None

                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    content=content,
                    timestamp=timestamp,
                    metadata=parsed
                )
            except json.JSONDecodeError:
                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    content=content
                )


def parse_firewall(artefact, path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            content = line.strip()
            if not content:
                continue

            parts = content.split(",")
            timestamp = None
            try:
                timestamp = make_aware(datetime.fromisoformat(parts[0]))
            except Exception:
                pass

            LogRecord.objects.create(
                artefact=artefact,
                record_index=i + 1,
                timestamp=timestamp,
                content=content
            )


def parse_plain_text(artefact, path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            content = line.strip()
            if content:
                LogRecord.objects.create(
                    artefact=artefact,
                    record_index=i + 1,
                    content=content
                )
