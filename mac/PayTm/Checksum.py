# import base64
# import string
# import random
# import hashlib

# from Crypto.Cipher import AES


# IV = "@@@@&&&&####$$$$"
# BLOCK_SIZE = 16


# def generate_checksum(param_dict, merchant_key, salt=None):
#     params_string = __get_param_string__(param_dict)
#     salt = salt if salt else __id_generator__(4)
#     final_string = '%s|%s' % (params_string, salt)

#     hasher = hashlib.sha256(final_string.encode())
#     hash_string = hasher.hexdigest()

#     hash_string += salt

#     return __encode__(hash_string, IV, merchant_key)

# def generate_refund_checksum(param_dict, merchant_key, salt=None):
#     for i in param_dict:
#         if("|" in param_dict[i]):
#             param_dict = {}
#             exit()
#     params_string = __get_param_string__(param_dict)
#     salt = salt if salt else __id_generator__(4)
#     final_string = '%s|%s' % (params_string, salt)

#     hasher = hashlib.sha256(final_string.encode())
#     hash_string = hasher.hexdigest()

#     hash_string += salt

#     return __encode__(hash_string, IV, merchant_key)


# def generate_checksum_by_str(param_str, merchant_key, salt=None):
#     params_string = param_str
#     salt = salt if salt else __id_generator__(4)
#     final_string = '%s|%s' % (params_string, salt)

#     hasher = hashlib.sha256(final_string.encode())
#     hash_string = hasher.hexdigest()

#     hash_string += salt

#     return __encode__(hash_string, IV, merchant_key)


# def verify_checksum(param_dict, merchant_key, checksum):
#     # Remove checksum
#     if 'CHECKSUMHASH' in param_dict:
#         param_dict.pop('CHECKSUMHASH')

#     # Get salt
#     paytm_hash = __decode__(checksum, IV, merchant_key)
#     salt = paytm_hash[-4:]
#     calculated_checksum = generate_checksum(param_dict, merchant_key, salt=salt)
#     return calculated_checksum == checksum

# def verify_checksum_by_str(param_str, merchant_key, checksum):
#     # Remove checksum
#     #if 'CHECKSUMHASH' in param_dict:
#         #param_dict.pop('CHECKSUMHASH')

#     # Get salt
#     paytm_hash = __decode__(checksum, IV, merchant_key)
#     salt = paytm_hash[-4:]
#     calculated_checksum = generate_checksum_by_str(param_str, merchant_key, salt=salt)
#     return calculated_checksum == checksum



# def __id_generator__(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
#     return ''.join(random.choice(chars) for _ in range(size))


# def __get_param_string__(params):
#     params_string = []
#     for key in sorted(params.keys()):
#         if("REFUND" in params[key] or "|" in params[key]):
#             respons_dict = {}
#             exit()
#         value = params[key]
#         params_string.append('' if value == 'null' else str(value))
#     return '|'.join(params_string)


# __pad__ = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
# __unpad__ = lambda s: s[0:-ord(s[-1])]


# def __encode__(to_encode, iv, key):
#     # Pad
#     to_encode = __pad__(to_encode)
#     # Encrypt
#     c = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
#     to_encode = c.encrypt(to_encode.encode('utf-8'))
#     # Encode
#     to_encode = base64.b64encode(to_encode)
#     return to_encode.decode("UTF-8")


# def __decode__(to_decode, iv, key):
#     # Decode
#     to_decode = base64.b64decode(to_decode)
#     # Decrypt
    

#     c = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
#     to_decode = c.decrypt(to_decode)
#     if type(to_decode) == bytes:
#         # convert bytes array to str.
#         to_decode = to_decode.decode()
#     # remove pad
#     return __unpad__(to_decode)


# if __name__ == "__main__":
#     params = {
#         "MID": "DummyMerchant12345",
#         "ORDER_ID": "order_id",
#         "CUST_ID": "cust_id",
#         "TXN_AMOUNT": "1",
#         "CHANNEL_ID": "WEB",
#         "INDUSTRY_TYPE_ID": "Retail",
#         "WEBSITE": "WEBSTAGING"
#     }

#     print(verify_checksum(
#         params, '12345678901234567890123456789012',
#         "CD5ndX8VVjlzjWbbYoAtKQIlvtXPypQYOg0Fi2AUYKXZA5XSHiRF0FDj7vQu66S8MHx9NaDZ/uYm3WBOWHf+sDQAmTyxqUipA7i1nILlxrk="))

#     # print(generate_checksum(params, "xxxxxxxxxxxxxxxx"))


import base64
import string
import random
import hashlib
from Crypto.Cipher import AES

IV = "@@@@&&&&####$$$$"
BLOCK_SIZE = 16

def generate_checksum(param_dict, merchant_key, salt=None):
    params_string = __get_param_string__(param_dict)
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (params_string, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()

    hash_string += salt

    return __encode__(hash_string, IV, merchant_key)

def verify_checksum(param_dict, merchant_key, checksum):
    # Remove checksum from param_dict if present
    if 'CHECKSUMHASH' in param_dict:
        param_dict.pop('CHECKSUMHASH')

    # Decode the received checksum
    try:
        paytm_hash = __decode__(checksum, IV, merchant_key)
    except Exception as e:
        print(f"Error during decoding: {e}")
        return False
    
    # Extract salt (last 4 characters)
    salt = paytm_hash[-4:]
    # Regenerate checksum with the extracted salt
    calculated_checksum = generate_checksum(param_dict, merchant_key, salt=salt)
    
    # Compare the recalculated checksum with the received one
    return calculated_checksum == checksum

# Helpers
def __id_generator__(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))

def __get_param_string__(params):
    params_string = []
    for key in sorted(params.keys()):
        if "REFUND" in params[key] or "|" in params[key]:
            return ""  # Exit if an invalid param is found
        value = params[key]
        params_string.append('' if value == 'null' else str(value))
    return '|'.join(params_string)

__pad__ = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
__unpad__ = lambda s: s[:-ord(s[-1])]

def __encode__(to_encode, iv, key):
    # Pad the string
    to_encode = __pad__(to_encode)
    # Create AES cipher object and encrypt the padded string
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    encrypted = cipher.encrypt(to_encode.encode('utf-8'))
    # Base64 encode the encrypted data
    return base64.b64encode(encrypted).decode("utf-8")

def __decode__(to_decode, iv, key):
    # Base64 decode the input checksum
    decoded = base64.b64decode(to_decode)
    # Create AES cipher object and decrypt
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    decrypted = cipher.decrypt(decoded)
    # Unpad the decrypted string
    return __unpad__(decrypted.decode('utf-8'))

# Testing the functions
if __name__ == "__main__":
    params = {
        "MID": "DummyMerchant12345",
        "ORDER_ID": "order_id",
        "CUST_ID": "cust_id",
        "TXN_AMOUNT": "1",
        "CHANNEL_ID": "WEB",
        "INDUSTRY_TYPE_ID": "Retail",
        "WEBSITE": "WEBSTAGING"
    }

    # Test checksum generation and verification
    merchant_key = '12345678901234567890123456789012'  # 32-byte key
    generated_checksum = generate_checksum(params, merchant_key)
    
    print("Generated Checksum:", generated_checksum)
    
    is_valid = verify_checksum(params, merchant_key, generated_checksum)
    print("Is Checksum Valid?", is_valid)
