import base64


def encode_payload(payload, salt_key, salt_index):
    """Encodes the payload with a salt key inserted at a given index."""
    if salt_index > len(payload):
        raise ValueError("Salt index is out of payload length.")
    modified_payload = payload[:salt_index] + salt_key + payload[salt_index:]
    encoded_payload = base64.b64encode(modified_payload.encode()).decode()
    return encoded_payload


def decode_payload(encoded_payload, salt_key, salt_index):
    """Decodes the payload if the correct salt key and index are provided."""
    decoded_bytes = base64.b64decode(encoded_payload)
    decoded_payload = decoded_bytes.decode()
    expected_salt_part = decoded_payload[salt_index : salt_index + len(salt_key)]
    if expected_salt_part != salt_key:
        return "Incorrect salt key or salt index. Cannot decode properly."
    original_payload = (
        decoded_payload[:salt_index] + decoded_payload[salt_index + len(salt_key) :]
    )
    return original_payload


# Example usage
payload = "HelloWorld"
salt_key = "Secret"
salt_index = 5

encoded = encode_payload(payload, salt_key, salt_index)
print(f"Encoded: {encoded}")

decoded = decode_payload(encoded, salt_key, salt_index)
print(f"Decoded: {decoded}")

# Attempting to decode with incorrect salt key or index
incorrect_salt_key = "Wrong"
incorrect_salt_index = 3
wrong_decoded = decode_payload(encoded, incorrect_salt_key, incorrect_salt_index)
print(f"Decoded with incorrect salt: {wrong_decoded}")
