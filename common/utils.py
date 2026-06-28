# ╔══════════════════════════════════════════════════════════════╗
# ║         Script Kittens — Free Fire UID Bypass               ║
# ║  Developers  :  1shot  &  Zen                               ║
# ║  Discord     :  discord.gg/8C3hw3Cyb2                       ║
# ║  Join for more projects, tools & community support!         ║
# ╚══════════════════════════════════════════════════════════════╝

import json
import codecs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser

# ================= Crypto Utils =================

def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N:
            BesTo |= 0x80
        H.append(BesTo)
        if not N:
            break
    return bytes(H)

def DEc_Uid(H):
    n = s = 0
    for b in bytes.fromhex(H):
        n |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            break
    return n

def CrEaTe_VarianT(field_number, value):
    field_number = int(field_number)
    return EnC_Vr((field_number << 3) | 0) + EnC_Vr(int(value))

def CrEaTe_LenGTh(field_number, value):
    field_number = int(field_number)
    if isinstance(value, (bytes, bytearray)):
        encoded_value = bytes(value)
    elif isinstance(value, str):
        encoded_value = value.encode('latin-1', 'replace')
    else:
        encoded_value = str(value).encode()
    return EnC_Vr((field_number << 3) | 2) + EnC_Vr(len(encoded_value)) + encoded_value

def encrypt_api(plain_text):
    if isinstance(plain_text, (bytes, bytearray)):
        plain_bytes = bytes(plain_text)
    else:
        plain_bytes = bytes.fromhex(plain_text)
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_bytes, AES.block_size))
    return cipher_text.hex()

def aes_decrypt(cipher_text):
    if isinstance(cipher_text, (bytes, bytearray)):
        cipher_bytes = bytes(cipher_text)
    else:
        cipher_bytes = bytes.fromhex(cipher_text)
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if len(cipher_bytes) % AES.block_size != 0:
        cipher_bytes = pad(cipher_bytes, AES.block_size)
    decrypted = cipher.decrypt(cipher_bytes)
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        return decrypted

# ================= Protobuf Utils =================

def _to_bytes(val):
    if isinstance(val, (bytes, bytearray)):
        return bytes(val)
    if isinstance(val, str):
        try:
            s = codecs.decode(val, "unicode_escape")
            return s.encode("latin-1", "replace")
        except Exception:
            return val.encode("utf-8", "replace")
    if isinstance(val, dict):
        return CrEaTe_ProTo(val)
    return str(val).encode()

def CrEaTe_ProTo(fields):
    if isinstance(fields, str):
        fields = json.loads(fields)
    packet = bytearray()
    for key, entry in fields.items():
        field_num = int(key)
        if isinstance(entry, dict) and "wire_type" in entry:
            wt = entry.get("wire_type")
            val = entry.get("data")
            if wt == "varint":
                packet.extend(CrEaTe_VarianT(field_num, int(val)))
            elif wt in ("string", "bytes"):
                packet.extend(CrEaTe_LenGTh(field_num, _to_bytes(val)))
            elif wt in ("length_delimited",):
                if isinstance(val, dict):
                    nested = CrEaTe_ProTo(val)
                else:
                    nested = _to_bytes(val)
                packet.extend(CrEaTe_LenGTh(field_num, nested))
            else:
                if isinstance(val, int):
                    packet.extend(CrEaTe_VarianT(field_num, int(val)))
                elif isinstance(val, dict):
                    packet.extend(CrEaTe_LenGTh(field_num, CrEaTe_ProTo(val)))
                else:
                    packet.extend(CrEaTe_LenGTh(field_num, _to_bytes(val)))
        else:
            if isinstance(entry, int):
                packet.extend(CrEaTe_VarianT(field_num, entry))
            elif isinstance(entry, dict):
                packet.extend(CrEaTe_LenGTh(field_num, CrEaTe_ProTo(entry)))
            else:
                packet.extend(CrEaTe_LenGTh(field_num, _to_bytes(entry)))
    return bytes(packet)

def parse_results(parsed_results):
    """Parse protocol buffer results"""
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    """Get available room from input text"""
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
