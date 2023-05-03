import hashlib, json, io, vt
from malwarebazaar import Bazaar

# VT_FILE = 'https://www.virustotal.com/api/v3/files'
# VT_HASH = "https://www.virustotal.com/api/v3/files/{}"
# VT_URL = 'https://www.virustotal.com/api/v3/urls'
# VT_IP = 'https://www.virustotal.com/api/v3/ip_addresses'
# VT_DOMAIN = 'https://www.virustotal.com/api/v3/domains'

HB_API = 'https://www.hybrid-analysis.com/api/v2'
OTX_API = 'http://otx.alienvault.com/api/v1'
URL_HAUS = 'https://urlhaus-api.abuse.ch/v1/url/'
URL_SCAN = "https://urlscan.io/api/v1/search/?q={}"

class PyJSON(object):
    def __init__(self, d):
        if type(d) is str:
            d = json.loads(d)

        self.from_dict(d)

    def from_dict(self, d):
        self.__dict__ = {}
        for key, value in d.items():
            if type(value) is dict:
                value = PyJSON(value)
            self.__dict__[key] = value

    def to_dict(self):
        d = {}
        for key, value in self.__dict__.items():
            if type(value) is PyJSON:
                value = value.to_dict()
            d[key] = value
        return d

    def __repr__(self):
        return str(self.to_dict())

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def __getitem__(self, key):
        return self.__dict__[key]
    
def file_scan(file, APIKey, filename, sha256):
    result = virustotal(sha256, "hash", APIKey)
    if hasattr(result, 'code'):
        result = virustotal(file, "file", APIKey, filename)
        if not hasattr(result, 'code'):
            result = virustotal(result, "analysis", APIKey)
    return result

def hash_scan(hash, APIKey):
    result = virustotal(hash, "hash", APIKey)
    if hasattr(result, 'code'):
        result = malwarebazaar(hash, APIKey)
    return result

def virustotal(data, data_type, APIKey, filename='unknown'):
    if APIKey.VTAPI:
        with vt.Client(APIKey.VTAPI) as client:
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
    else:
        result = PyJSON({'code': 'VirusTotalError', 'message': 'API key can not be an empty string.'})
        return result
    
def malwarebazaar(hash, APIKey):
    if APIKey.MBAPI:
        bz = Bazaar(api_key=APIKey.MBAPI)
        response = bz.query_hash(hash)
        if response.get('query_status') == "ok":
            result = response["data"][0] #PyJSON(response["data"][0])
            return result
        else:
            result = PyJSON({'code': 'HashQueryError', 'message': f'No matches found => {response["query_status"]}'})
            return result
    else:
        result = PyJSON({'code': 'MalwareBazaarError', 'message': 'API key can not be an empty string.'})
        return result
    
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