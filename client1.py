from socket import *
import sys
import hmac
import hashlib
import rsa
import random
from AES import main_encrypt


def hash_client_authenticate(connection, key):
    message = connection.recv(32)
    hashlib.new('sha256')
    xash = hmac.new(key, message, digestmod='sha256')
    digest = xash.digest()
    connection.send(digest)  # send response to server


def use_public_key(data):
    data = data.decode('utf-8')
    k = len(data)
    public_key = data[10: k - 8]
    public_key = int(public_key)
    return public_key


def create_session_key(data):
    p = random.randint(10000000, 99999999)
    print("Session key: ", p)
    p = str(p)
    pas = p.encode('utf-8')
    psd = rsa.encrypt(pas, rsa.PublicKey(use_public_key(data), 65537))
    return psd, p


def padding(raw_text):
    while len(raw_text) % 8 != 0:
        raw_text += b' '
    return raw_text


def aes_encrypt(text, key):
    text = bytes(text, 'utf-8')
    padding_message = padding(text)
    encrypted_message = main_encrypt(padding_message, key.decode())
    return encrypted_message


def echo_client(address, key):
    # tcp_socket содержит сокеты TCP/IP, т.е. TCP/IP объявляем в переменную
    tcp_socket = socket(AF_INET)
    # Подключаемся
    tcp_socket.connect(address)
    data_rsa = tcp_socket.recv(1024)
    # Сеансовый ключ
    rsa_message, session_key = create_session_key(data_rsa)
    tcp_socket.send(rsa_message)
    hash_client_authenticate(tcp_socket, password)

    while True:
        message = input("Введите ваше сообщение: ")
        if message == 'quit':
            break
        # AES encrypt
        message_aes = aes_encrypt(message, key)
        print("Отправляем зашифрованное сообщение с помощью AES на сервер:", message_aes.split())
        tcp_socket.send(message_aes)
        server_msg = tcp_socket.recv(1024)
        print(server_msg.decode('utf-8'))
    tcp_socket.close()


if __name__ == '__main__':
    start = True
    if len(sys.argv) != 2 or sys.argv[1] != '000000':
        print("Неверный пароль")
        start = False
    else:
        password = sys.argv[1].encode('utf-8')
    if start:
        echo_client(('localhost', 1234), password)
