import hashlib, requests, json, vt

VT_FILE = 'https://www.virustotal.com/api/v3/files'
VT_HASH = "https://www.virustotal.com/api/v3/files/{}"
VT_URL = 'https://www.virustotal.com/api/v3/urls'
VT_IP = 'https://www.virustotal.com/api/v3/ip_addresses'
VT_DOMAIN = 'https://www.virustotal.com/api/v3/domains'

HB_API = 'https://www.hybrid-analysis.com/api/v2'
OTX_API = 'http://otx.alienvault.com/api/v1'
URL_HAUS = 'https://urlhaus-api.abuse.ch/v1/url/'
URL_SCAN = "https://urlscan.io/api/v1/search/?q={}"

def file_scan(file, case, APIKey):
    if APIKey.VTAPI and case.virustotal:
        sha256 = hash(file.read(), hash_type="sha256")
        result = virustotal(sha256, "hash", APIKey.VTAPI)
        if result.code and result.message:
            result = virustotal(file, "file", APIKey.VTAPI)
            if not result.code and not result.message:
                result = virustotal(result, "analysis", APIKey.VTAPI)
        return result
    
    elif APIKey.MBAPI and case.malwarebazaar:
        print(1)


def virustotal(data, data_type, apikey):
    with vt.Client(apikey) as client:
        try:
            if data_type == "file":
                # Upload a file for scanning: scan and analyse a file
                analysis = client.scan_file(data)
                return analysis
            
            elif data_type == "hash":
                # Get a file report by hash: Retrieve information about a file
                file_hash = client.get_object("/files/{}", data)
                return file_hash
            
            elif data_type == "analysis":
                # Get a URL/file analysis report: Returns a Analysis object.
                analysis = client.get_object("/analyses/{}", data.id)
                print(analysis.status)
                return analysis
            
        except vt.error.APIError as e:
            return e

def hash(value, hash_type="sha1"):
    """Example filter providing custom Jinja2 filter - hash
        :param value: value to be hashed
        :param hash_type: valid hash type
        :return: computed hash as a hexadecimal string | hash('md5')
    """
    hash_func = getattr(hashlib, hash_type, None)
    if hash_func:
        computed_hash = hash_func(value).hexdigest()
    else:
        raise AttributeError(
            "No hashing function named {hname}".format(hname=hash_type)
        )
    return computed_hash