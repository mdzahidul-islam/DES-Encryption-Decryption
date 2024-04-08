# two working modes implementation, namely ECB and CBC

from des_base import DesBase

DES = DesBase()


class WorkingModes:

    def __init__(self, key_byte, IV=None, modes="ECB", file_type="file"):
        self.sub_keys = DES.key_gen(key_byte)
        self.IV = IV
        self.modes = modes
        self.file_type = file_type
        return

    def _msg2block(self, data):
        orig_msg_blocks = []
        if self.file_type != "file":
            data = data.encode()
        self.data_len = len(data)
        for block in range(self.data_len // 8):
            msg_block = data[block * 8:(block + 1) * 8]
            orig_msg_blocks.append(msg_block)
        if len(data) % 8 != 0:
            last_block = DES.padding(data[len(orig_msg_blocks) * 8:])
            orig_msg_blocks.append(last_block)
        return orig_msg_blocks

    def encrypt(self, msg_str):
        orig_msg_blocks = self._msg2block(msg_str)
        orig_block_encryption = bytearray()

        if self.modes == "ECB":
            for block in orig_msg_blocks:
                encoded_data = DES.desEncDec(block, 1, self.sub_keys)  # 1 for encoding
                orig_block_encryption += encoded_data

        elif self.modes == "CBC":
            iv = self.IV
            for block in orig_msg_blocks:
                xor_block = bytes(a ^ b for (a, b) in zip(block, iv))
                encoded_data = DES.desEncDec(xor_block, 1, self.sub_keys)  # 1 for encoding
                orig_block_encryption += encoded_data
                iv = encoded_data

        return orig_block_encryption

    def decrypt(self, orig_block_encryption):
        decoded_msg = bytearray()

        if self.modes == "ECB":
            for block in range(len(orig_block_encryption) // 8):
                decoded_block = DES.desEncDec(orig_block_encryption[block * 8:(block + 1) * 8], 2,
                                              self.sub_keys)  # 2 for decoding
                decoded_msg += decoded_block

        elif self.modes == "CBC":
            iv = self.IV
            for block in range(len(orig_block_encryption) // 8):
                cipher_blk = orig_block_encryption[block * 8:(block + 1) * 8]
                decoded_block = DES.desEncDec(cipher_blk, 2, self.sub_keys)  # 2 for decoding
                decoded_block = bytes(a ^ b for (a, b) in zip(decoded_block, iv))
                decoded_msg += decoded_block
                iv = cipher_blk

        if self.data_len % 8 != 0:
            decoded_msg = DES.un_padding(decoded_msg)
        if self.file_type != "file":
            decoded_msg = decoded_msg.decode()
        return decoded_msg
