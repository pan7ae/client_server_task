from socket import *
import time
import hmac
import os
import hashlib
import rsa
from AES import main_decrypt


def hash_server_authenticate(connection, key):
    message = os.urandom(32)
    connection.send(message)
    hashlib.new('sha256')
    xash = hmac.new(key, message, digestmod='sha256')
    digest = xash.digest()
    response = connection.recv(len(digest))
    return hmac.compare_digest(digest, response)


def rsa_authenticate(connection):
    # Генерирование открытых и закрытых ключей
    (public_key, private_key) = rsa.newkeys(1024)
    public_key = str(public_key)
    connection.send(public_key.encode('utf-8'))
    session_key = connection.recv(1024)
    print("Сеансовый ключ по расшифровки ", session_key)
    session_key = rsa.decrypt(session_key, private_key)
    print("Сеансовый ключ от клиента:", session_key)
    print("Успешное соединение!")
    return session_key


def echo_handler(client_sock, key):
    if not hash_server_authenticate(client_sock, secret_key):
        client_sock.close()
        return

    while True:
        # Получаем сообщения от клиента
        client_message = client_sock.recv(1024)
        if client_message == "quit":
            break
        # Расшифровываем
        client_message = main_decrypt(client_message, key.decode())
        print("Расшифровываем полученное сообщение с помощью AES: ", client_message)
        # Время
        now_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        # Отправляем сообщение клиенту
        client_sock.send((str(now_time) + ' -> ' + str(client_message)).encode('utf-8'))

    client_sock.close()


def echo_server(address):
    # tcp_server содержит сокеты TCP/IP, т.е. TCP/IP объявляем в переменную
    tcp_server = socket(AF_INET, SOCK_STREAM)
    # Объявляем этот протокол на создание address (hostname и port)
    tcp_server.bind(address)
    # "Прослушиваем"
    tcp_server.listen()
    # Принимаем подключение (сокет и адрес клиента)
    client_socket, client_address = tcp_server.accept()
    session_key_rsa = rsa_authenticate(client_socket)
    return session_key_rsa, client_socket


if __name__ == '__main__':
    secret_key = b'000000'
    session_key, client_socket = echo_server(('', 1234))
    echo_handler(client_socket, secret_key)  # hash_server_authenticate
