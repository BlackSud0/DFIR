import hashlib

def hash(value, hash_type="sha1"):
    """Example filter providing custom Jinja2 filter - hash
        :param value: value to be hashed
        :param hash_type: valid hash type
        :return: computed hash as a hexadecimal string | hash('md5')
    """
    hash_func = getattr(hashlib, hash_type, None)
    if hash_func:
        computed_hash = hash_func(value.encode("utf-8")).hexdigest()
    else:
        raise AttributeError(
            "No hashing function named {hname}".format(hname=hash_type)
        )
    return computed_hash