import json
import time
from typing import List, Optional

import requests
from Cryptodome.Cipher import AES
from gmssl import sm3, func
from gmssl.sm4 import CryptSM4, SM4_DECRYPT


class Sszycn:
    def __init__(
            self,
            phone_number: int,
            session_cookie: str,
            fragment_file: str
    ):
        """
        师生之友 SszyCN Fragment Decrypter
        Author: github.com/DevLARLEY
        """
        self._phone_number = phone_number
        self._session_cookie = session_cookie
        self._fragment_file = fragment_file

        self._key_epoch = int(time.time())
        self._key_id = self.sm3_hash_key_id(fragment_file, phone_number, self._key_epoch)

    @staticmethod
    def sm3_hash_key_id(fragment_file: str, phone_number: int, epoch_seconds: int) -> str:
        sm3_data = (fragment_file + str(phone_number) + str(epoch_seconds)).encode()
        return sm3.sm3_hash(func.bytes_to_list(sm3_data))

    def get_license(self) -> Optional[str]:
        response = requests.get(
            url='https://www.sszycn.com/student/handout/license',
            params={
                'f': self._fragment_file,
                'keywhen': self._key_epoch,
                'keyid': self.sm3_hash_key_id(self._fragment_file, self._phone_number, self._key_epoch),
            },
            cookies={
                'SESSION': self._session_cookie
            },
        )

        if response.status_code != 200:
            return

        return response.text

    @staticmethod
    def sm4_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> str:
        sm4_crypt = CryptSM4()
        sm4_crypt.set_key(key, SM4_DECRYPT)

        decrypted_data = sm4_crypt.crypt_cbc(iv, ciphertext)
        return decrypted_data.decode()

    def decrypt_license(self, license_message: str) -> List[str]:
        parsed_license = json.loads(license_message)

        key_hash_payload = (str(self._phone_number) + parsed_license["keyid"] + parsed_license["keywhen"]).encode()
        key = sm3.sm3_hash(func.bytes_to_list(key_hash_payload))[:32]

        iv_hash_payload = (str(self._phone_number) + parsed_license["keywhen"]).encode()
        iv = sm3.sm3_hash(func.bytes_to_list(iv_hash_payload))[:32]

        decrypted_metadata = self.sm4_decrypt(
            key=bytes.fromhex(key),
            iv=bytes.fromhex(iv),
            ciphertext=bytes.fromhex(parsed_license["license"])
        )

        return json.loads(decrypted_metadata)

    @staticmethod
    def _decrypt_chunk_aesctr(chunk: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(
            key=key,
            mode=AES.MODE_CTR,
            nonce=iv[:8],
            initial_value=int.from_bytes(iv[8:16], byteorder='big')
        )
        return cipher.decrypt(chunk)

    @staticmethod
    def _crypto_js_ctr_decrypt(encrypted_data: bytes, key: str, iv: str) -> bytes:
        parsed_key = key.encode('latin-1')
        parsed_iv = iv.encode('latin-1')

        decrypted_data = bytearray()
        chunk_size = 8192

        for offset in range(0, len(encrypted_data), chunk_size):
            current_chunk = encrypted_data[offset:min(offset + chunk_size, len(encrypted_data))]
            decrypted_chunk = Sszycn._decrypt_chunk_aesctr(current_chunk, parsed_key, parsed_iv)
            decrypted_data.extend(decrypted_chunk)

        return bytes(decrypted_data)

    @staticmethod
    def decrypt_fragment(in_file: str, out_file: str, key: str, iv: str) -> None:
        with open(in_file, "rb") as f:
            in_data = f.read()

        decrypted = Sszycn._crypto_js_ctr_decrypt(in_data, key, iv)

        with open(out_file, "wb") as f:
            f.write(decrypted)


if __name__ == '__main__':
    # "SESSION" cookie
    cookie = ""
    file = "00000000-1111-2222-3333-44444444444444.ts"
    mobile_number = 100000000000

    sszycn = Sszycn(
        phone_number=mobile_number,
        session_cookie=cookie,
        fragment_file=file
    )

    licence = sszycn.get_license()

    if not licence:
        print("Unable to request license:", licence)
        exit()

    decrypted_license = sszycn.decrypt_license(licence)

    # Note: file must be in current directory
    sszycn.decrypt_fragment(file, file + "_decrypted.ts", decrypted_license[0], decrypted_license[1])
