def infer_artefact_type(filename):
    ext = filename.lower().split('.')[-1]
    if ext == 'evtx':
        return 'evtx'
    elif ext in ['pcap', 'pcapng']:
        return 'pcap'
    elif ext in ['xml', 'json', 'txt', 'log']:
        return 'other'
    return 'other'
