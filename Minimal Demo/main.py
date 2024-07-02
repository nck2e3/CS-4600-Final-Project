import glob
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import pickle
import os


class RSA_User:
    """
    Creating an object in the platonic tradition...

    This class does the following:
    -Encapsulates the functionality and data pertaining to public-key cryptography.
    -Associates a public-private key pair (and related files) with the name of a particular user.
    """
    def __init__(self, name):
        self.name = name
        #Public and private keys, akin to the hermetic principle of polarity...
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key()
        self.private_filename = os.path.join(os.path.dirname(__file__), f"private_key_{self.name}.pem") #Make sure files are made in same directory as running script...
        self.public_filename = os.path.join(os.path.dirname(__file__), f"public_key_{self.name}.pem")   #Make sure files are made in same directory as running script...
    def writeToFile(self):
        with open(self.private_filename, 'wb') as file:
            file.write(self.private_key.export_key())
        with open(self.public_filename, 'wb') as file:
            file.write(self.public_key.export_key())


class Packet():
    """
    Encapsulate all the transmission stuff in a single class...

    This class does the following:
    -Encapsulates all functions related to the encryption and decryption of messages, both symmetrically and assymetrically.
    """

    @staticmethod
    def encrypt(public_key_recipient_file, message):
        #AES-256 Symmetric Encryption...                             #Fat bytes raise your cholesterol...
        aes_key = os.urandom(32)                                     #Byte Width (key)        : 32       | AES-256, 32*8 = 128 bits...
        nonce = os.urandom(12)                                       #Byte Width (nonce)      : 12       | As per NIST recommendations...
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce)           #Galois Counter Mode (GCM) is considered the most secure in 2024...        
        ciphertext, GCM_tag = aes_cipher.encrypt_and_digest(message) #Byte Width (TAG)        : 16       | In GCM mode, the GCM tag serves the purpose of a traditional MAC or HMAC...
                                                                     #Byte Width (ciphertext) : Variable | Because we know the widths of all other fields, solving for this is easy...
        with open(public_key_recipient_file, 'rb') as file:          #Loading RSA public key of message recipient...
            public_key_recipient = RSA.import_key(file.read())
       
        #Encrypting AES key using RSA public key of the recipient...
        rsa_cipher = PKCS1_OAEP.new(public_key_recipient)
        aes_key_encrypted = rsa_cipher.encrypt(aes_key)

        #Serializing the data using pickle to make decoding and decrypting easier (we know all byte widths except the ciphertext, decoding will be easy)...
        serialized_packet = pickle.dumps((GCM_tag, aes_key_encrypted, nonce, ciphertext))
        return serialized_packet
    
    @staticmethod
    def decrypt(private_key_recipient_file, serialized_packet):
        #Unpacking the serialized packet...
        GCM_tag, aes_key_encrypted, nonce, ciphertext = pickle.loads(serialized_packet)
        
        #Loading RSA private key of message recipient...
        with open(private_key_recipient_file, 'rb') as file:
            private_key_recipient = RSA.import_key(file.read())

        #Decrypting the AES key using RSA private key...
        rsa_cipher = PKCS1_OAEP.new(private_key_recipient)
        aes_key = rsa_cipher.decrypt(aes_key_encrypted)
        
        #Using the recovered AES key, decrypt the message using...
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce)

        #Verify the authenticity of the message, throw error when GCM TAG (a type of MAC) doesn't match...
        try:
            message = aes_cipher.decrypt_and_verify(ciphertext, GCM_tag)
        except ValueError:
            message = b"Failure to verify authenticity and/or integrity of the message. (GCM TAG FAILURE)"
        return message.decode('utf-8')

def main():
    """
    The main function is a demo function that creates the RSA keypairs of the function, writes them to files, and initates a loop in which
    the user chooses which test case they would like to show...
    """

    #Generating RSA keypairs...
    RSA_Alice = RSA_User("Alice")
    RSA_Bob = RSA_User("Bob")

    #Writing these keypairs to files...
    RSA_Alice.writeToFile()
    RSA_Bob.writeToFile()

    #SIMPLE DEMO - Alice sends a message to Bob
    message = "THIS IS A MESSAGE"
  
    #Unencrypted message prior to transmission, see encrypt() function in Packet class for more details...
    print(f"\nUNENCRYPTED MESSAGE (Alice's End before Transmission): {message}")
    
    #Message in Transit to Recipient, encrypt message before transmission...
    encrypted_message = Packet.encrypt(RSA_Bob.public_filename, message.encode('utf-8'))
    print(f"\n[BEGIN ENCRYPTED MESAGE IN TRANSIT]\n{encrypted_message}\n[END ENCRYPTED MESAGE IN TRANSIT]\n") 

    #Writing encrypted message to a file (also make sure file is created in same directory as running script)...
    transmitted_message_filename = os.path.join(os.path.dirname(__file__), f"TRANSMITTED MESSAGE (Alice to Bob).txt")
    with open(transmitted_message_filename, 'wb') as file:
        file.write(encrypted_message)

    #Message upon delivery to recipient, see decrypt() function in Packet class for more details...
    decrypted_message = Packet.decrypt(RSA_Bob.private_filename, encrypted_message)
    print(f"Decrypted Message ({RSA_Bob.name}'s End): {decrypted_message}\n")
    


if __name__ == "__main__":
    main()