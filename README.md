# CS-4600 Final Project

## Overview

This project demonstrates the implementation of public-key cryptography using RSA and AES encryption techniques. It includes a simple command-line interface to allow two users, Alice and Bob, to securely transmit messages to each other. The project is developed in Python and utilizes the PyCryptodome library for cryptographic operations.

## Features

- **RSA Key Pair Generation**: Generates RSA public and private keys for each user.
- **AES Encryption**: Uses AES-256 Galois/Counter Mode (GCM) for secure message encryption.
- **Asymmetric Encryption**: Encrypts the AES key using RSA public key of the recipient.
- **Message Transmission**: Simulates the transmission of encrypted messages between users.
- **Message Decryption**: Decrypts the received message using the recipient's RSA private key and AES key.

## Prerequisites

- Python 3.6 or higher
- PyCryptodome library

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/nck2e3/CS-4600-Final-Project.git
    cd CS-4600-Final-Project
    ```

2. **Install Dependencies**:
    ```bash
    pip install pycryptodome
    ```

## Usage (Complex Demo)

1. **Run the Script**:
    ```bash
    python main.py
    ```

2. **Select an Option**:
    - Transmit message from Alice to Bob
    - Transmit message from Bob to Alice
    - Exit

3. **Follow the Prompts**:
    - Enter the message you want to send.
    - The script will display the unencrypted message, the encrypted message in transit, and the decrypted message at the recipient's end.

4. **Observe**: 
    - Key Generation (".PEM" files)
    - Message File (".txt" file)
    - Console Output

## Usage (Simple Demo)

1. **Run the Script**:
    ```bash
    python main.py
    ```

2. **Observe**: 
    - Key Generation (".PEM" files)
    - Message File (".txt" file)
    - Console Output