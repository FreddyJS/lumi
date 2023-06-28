from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

KEY  = "14773c9392e9705d28402b6385a0fd74"
IV   = "64e3be8e20464b533fe2231ff811d36b"

# Extracted UDP payloads to use as examples
RESULT_OK  = "213100400000000005389c6a649c8de866e53888cf89dee026eb7bf571bb3e8ea368cc68edbe2d669e7a5e213594cc91c5f89b009c235ba73c63e56776ac96ab"
OTC_LIST   = "213101a00000000005389c6a649c8d9ab07b8b921a520369c453eee43802c3f5930b7a3ce5d7dbd0484d59dd363f0eb3bd296a3d650108ab62457bc101a1c678f24f1ad781f4764c490cb16876deb9f18b147e1814d3dac37d41bc91d7f8bfd1927385f3ecfa2ca7d249a9ddbeda8c687581957e3138da8e025476b52b59837d90ebab2eadf85c74254cde3db7f8a2e5f9932060bd6720b4332717f80ef816465bb8b38a7d7b9f1c8e521a3cb4e32f63423163289efdbbf2af99f36b8dc49efd7a8fcc3ba3f674193ada71b439b4495d10ee243a0a38574516ca50a6814cb7f5346d0e1140e5266019a50e288775d91df0dbda8daeb31478da3c2283ed94a2a4ef8774c5b0f63decf88bf78f4ff5bbbc624632f390c279ffed5bdc1ea2248dcf897510d321bc02886aa901137f1f17bb43c517c5939edfadf07fa41cf968468bd8f1445f35393e6593bc804977a3ff08a86865eed776dd12a53370ef1ea6ad3dc5ad5a36edf65af6b0ca1b8604b511bd685625ba1654900805f7d4cd99e1fd34bd5f8be904c9c3d03210380cb7a1a26f9ee3f54513a1f8001d5cfc77e911d89b"
RGB_CHANGE = "213100a00000000005389c6a649ca1aa03eddce2ff14ec6cfb1718c2d9eace70961f22151a50e69f950e2df233d9a8c5c3924197ea04128ce05db409f30918fd767c12f841b60ef74dc19592623ed0d793aac0d681e5ecb70fac5680b43bfbd47ce0396485d7544a347cb406284b0713128128d8cbe7f0b58ab32d1b29fb544f79bf0c58f3bf10cce10e28a4890d8c7732502d33df345fbc862472f0d70f3cf6"
SET_SOUND  = "213100700000000005389c6a649ca2873b70b3669a37034aea7b04ef9ff0a28b961f22151a50e69f950e2df233d9a8c5c5e1e9320d6d8f96691fa1b6af3f8cb2c8fbad69509f14d372316458b2a7f3a718bfbd31b5aa48e75d82e22d0722e376672f41b928f07c44d9ee24d7a233d0d5"
OTC_INFO   = "213102200000000005389c6a649c90133d6eba1803325dca734b903a4adb3d8037b2e9465a48a13db60573f16015cc0c3e5ba740534e0afdf0fc519e4bd6938e4d8fe5d6842c9fed729e4ce08cfb82480a670f36822037ea0940321f518ec7148cc91d39b50d81821801b5125c50cc5290d6ba617d1ed24a06138b841a5d042d2d0e8adcdc4e2a1fff1b2a6c4c551cbd2a0fb5a752576f1088d07b6ae5ed00b4ac103089de92610692cfb2a504ddcd51f112a09783ce836819afa6803354501a394c3c312650f557bb17cd89d54fc7a637a4cd83e24d9b02ff47dda92a7fbf9e1c462863a7d89588a1bb5219888d85a36c039aec2051a4416a58cf98d7dfe141a231802635405df9b4727da0d1cb50fd83895c0acf41e4d854e0287b4595ff6f033cbe3b56141a125c5b2156a6314757d850b5e247487eed379e660bb48e5e2ea63512ee7789169de4cd6242eb28390e0ac63a6ee84c523ba21f0ba9f200e3308d5735f4a5c788348b604d79ea1ffb7e30022ec31aa1247f44c9eabc3bd5469729ef4f71ee725085aed4bafdf0d9518628808206886aceca1edb8567c1a76f653067db9472d6c00907b195900c312879f69c930b82a21ef87e0d17c9ae1e370cda54152fe657ca8a484f0bd93c32d4c10328cf125ac3bf1cd3aa8128f51943990948e4ef4823ae4af98e7a41acdaa2e4398b1ebc6530cbe31b8535dd0425831bd3808b4daf040b66b666124313496766f49eb9caebc238bf316a3f5944e06b6f"
HEARTBEAT  = "213100d00000000005389c6a649c9040b2492e7b4c5e0423754113b442a42571a3d9b65c0e86c16e2dc24c2c88b5afd88eb594fdc0178841a5ae821c67250c8d75485602aa6542d9b962c2badeefa335be1efd4061a5eb6e8fc36f538654511fc39da5d5e0450b765abfaff091939be7d60c0f7fffaa5e3cf197272c34851f405a43112803ab5504d7ed81baa9f91a40ec03b6e5311ea583fec861258201ac8cb335940272d9e28bc506cbf87db1fa4d6296cc5fcdbc422584577b827afa385c19f538c0d415e45ed0f37ee6bec91f22"

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    aes = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()

    return aes.update(padded_plaintext) + aes.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    padded_plaintext = aes.update(ciphertext) + aes.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

print("Key:      0x" + KEY)
print("IV:       0x" + IV)

KEY  = bytes.fromhex(KEY)
IV   = bytes.fromhex(IV)

def decrypt_message(data, key, iv):
    # First 16 bytes --> HEADER
    # header = data[:16]
    # checksum = data[16:32]
    data = data[32:]

    if len(data) != 0:
        text = aes_cbc_decrypt(key, iv, data)
    else:
        print("Message with no data")
        return
    
    print("Plaintext:")
    print(text)
    print()

print("Decrypting RESULT OK")
decrypt_message(bytes.fromhex(RESULT_OK), KEY, IV)

print("Decrypting OTC LIST")
decrypt_message(bytes.fromhex(OTC_LIST), KEY, IV)

print("Decrypting RGB CHANGE")
decrypt_message(bytes.fromhex(RGB_CHANGE), KEY, IV)

print("Decrypting SET SOUND")
decrypt_message(bytes.fromhex(SET_SOUND), KEY, IV)

print("Decrypting OTC INFO")
decrypt_message(bytes.fromhex(OTC_INFO), KEY, IV)

print("Decrypting HEARTBEAT")
decrypt_message(bytes.fromhex(HEARTBEAT), KEY, IV)
