from work_modes import WorkingModes

my_key = b'\x08\xaa\x99\x06\xaa\x99\x44\xcc'
my_IV = b'\x44\xac\xf9\x46\xca\xd3\xf1\x78'
my_choice = input("Input the working modes, 'ECB' or 'CBC': ")

input_type = input("If input type is String, write: 'str', else write: 'file': ")

# string input, file_type = "str"
if input_type == "str":
    my_msg = input("please input the message you want to encrypt/decrypt: ")
else:
    # select the image file to open, file_type="file"
    with open("test.png", "rb") as image:
        my_msg = image.read()
        my_msg = bytearray(my_msg)
    image.close()

# class instance
my_secure_func = WorkingModes(key_byte=my_key, IV=my_IV, modes=my_choice, file_type=input_type)

# encrypt the input
encrypt_secret = my_secure_func.encrypt(my_msg)

# decrypt the encrypted data
decrypt_secret = my_secure_func.decrypt(encrypt_secret)

# save encoded and decoded image file
if input_type == "str":
    print("encrypted msg: ", encrypt_secret)
    print("decrypted msg:  " + decrypt_secret)
else:
    with open("encrypted.png", "wb") as image:
        image.write(encrypt_secret)
    image.close()

    with open("decrypted.png", "wb") as image:
        image.write(decrypt_secret)
    image.close()

    print("completed the encryption and decryption, please check the directory")
