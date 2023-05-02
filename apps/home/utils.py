import hashlib, io, vt
# VT_FILE = 'https://www.virustotal.com/api/v3/files'
# VT_HASH = "https://www.virustotal.com/api/v3/files/{}"
# VT_URL = 'https://www.virustotal.com/api/v3/urls'
# VT_IP = 'https://www.virustotal.com/api/v3/ip_addresses'
# VT_DOMAIN = 'https://www.virustotal.com/api/v3/domains'

HB_API = 'https://www.hybrid-analysis.com/api/v2'
OTX_API = 'http://otx.alienvault.com/api/v1'
URL_HAUS = 'https://urlhaus-api.abuse.ch/v1/url/'
URL_SCAN = "https://urlscan.io/api/v1/search/?q={}"

def file_scan(file, case, APIKey, filename, sha256):
    if APIKey.VTAPI and case.virustotal:
        result = virustotal(sha256, "hash", APIKey.VTAPI)
        if hasattr(result, 'code'):
            result = virustotal(file, "file", APIKey.VTAPI, filename)
            if not hasattr(result, 'code'):
                result = virustotal(result, "analysis", APIKey.VTAPI)
        return result
    elif APIKey.HBAPI and case.hybridanalysis:
        return None
    else:
        return None

def virustotal(data, data_type, apikey, filename='unknown'):
    with vt.Client(apikey) as client:
        try:
            if data_type == "file":
                # Upload a file for scanning: scan and analyse a file
                file = io.BytesIO(data)
                file.name = filename
                analysis = client.scan_file(file)
                return analysis
            
            elif data_type == "hash":
                # Get a file report by hash: Retrieve information about a file
                file_hash = client.get_object("/files/{}", data)
                return file_hash
            
            elif data_type == "analysis":
                # Get a URL/file analysis report: Returns a Analysis object.
                analysis = client.get_object("/analyses/{}", data.id)
                return analysis
            
        except vt.error.APIError as e:
            return e

def hashid(value, hash_type="sha1"):
    """Example filter providing custom Jinja2 filter - hash
        :param value: value to be hashed
        :param hash_type: valid hash type
        :return: computed hash as a hexadecimal string | hashid('md5')
    """
    hash_func = getattr(hashlib, hash_type, None)
    if hash_func:
        computed_hash = hash_func(value).hexdigest()
    else:
        raise AttributeError(
            "No hashing function named {hname}".format(hname=hash_type)
        )
    return computed_hash

def get_size(file_size=12333, unit='bytes'):
    exponents_map = {'bytes': 0, 'kb': 1, 'mb': 2, 'gb': 3}
    if unit not in exponents_map:
        raise ValueError("Must select from \
        ['bytes', 'kb', 'mb', 'gb']")
    else:
        size = file_size / 1024 ** exponents_map[unit]
        return round(size, 3)