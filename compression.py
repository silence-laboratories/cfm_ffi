import zlib

# Compress data
original_data = b"Your large binary data..."
compressed_data = zlib.compress(original_data)

print(len(original_data))
print(len(compressed_data))

# Now you can send 'compressed_data' via your API.

# On the receiving side, decompress it:
decompressed_data = zlib.decompress(compressed_data)
assert original_data == decompressed_data
