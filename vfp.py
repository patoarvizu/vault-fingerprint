#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pyfingerprint.pyfingerprint import PyFingerprint
from cryptography.fernet import Fernet
import requests
import json
import hashlib
import click
import time

def __initSensor():
    try:
        f = PyFingerprint('/dev/ttyUSB0', 57600, 0xFFFFFFFF, 0x00000000)

        if ( f.verifyPassword() == False ):
            raise ValueError('The given fingerprint sensor password is wrong!')

    except Exception as e:
        print('The fingerprint sensor could not be initialized!')
        print('Exception message: ' + str(e))
        exit(1)

    return f

def __readUntilFound(f):
    while True:
        try:
            print('Waiting for finger...')
            while ( f.readImage() == False ):
                pass

            f.convertImage(0x01)
            result = f.searchTemplate()
            positionNumber = result[0]
            if ( positionNumber == -1 ):
                print('No match found!')
                continue

            break

        except Exception as e:
            print("Error processing fingerprint: " + str(e))
            print("Try again")
            continue

@click.group()
def main():
    pass

@main.command()
@click.option('-address', default='http://127.0.0.1:8200')
@click.option('-key-shares', default=5, type=int)
def init(address, key_shares):
    f = __initSensor()
    __readUntilFound(f)

    try:
        key = Fernet.generate_key()
        f = Fernet(key)

        payload = { 'secret_shares': key_shares, 'secret_threshold': key_shares, 'stored_shares': key_shares, 'recovery_shares': key_shares, 'recovery_threshold': key_shares }
        r = requests.put(address + '/v1/sys/init', data=json.dumps(payload), headers = { 'X-Vault-Request': 'true' })
        u = json.loads(r.text)

        encrypted_init_output = {}
        encrypted_keys = []
        for k in u["keys"]:
            encrypted_keys.append(f.encrypt(k.encode()))

        encrypted_init_output['encrypted_keys'] = encrypted_keys

        o = open("encrypted-init-output.json", "w")
        o.write(json.dumps(encrypted_init_output))
        o.close()

        key_file = open("fingerprint-encryption.key", "w")
        key_file.write(key)
        key_file.close()

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)

@main.command()
@click.option('-address', default='http://127.0.0.1:8200')
def unseal(address):
    f = __initSensor()
    __readUntilFound(f)

    try:
        key_file = open("fingerprint-encryption.key", "r")
        f = Fernet(key_file.read())

        o = open("encrypted-init-output.json", "r")
        e = json.loads(o.read())

        for unseal_key in e["encrypted_keys"]:
            payload = { 'key': f.decrypt(unseal_key.encode()) }
            r = requests.put(address + '/v1/sys/unseal', data=json.dumps(payload), headers = { 'X-Vault-Request': 'true' })


    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)

@main.command()
def enroll():
    f = __initSensor()

    while True:
        try:
            print('Waiting for finger...')
            while ( f.readImage() == False ):
                pass

            f.convertImage(0x01)
            result = f.searchTemplate()
            positionNumber = result[0]
            if ( positionNumber >= 0 ):
                print('Fingerprint already exists at position #' + str(positionNumber))
                exit(0)

            print('Remove finger...')
            time.sleep(2)
            print('Place same finger again...')
            while ( f.readImage() == False ):
                pass

            f.convertImage(0x02)
            if ( f.compareCharacteristics() == 0 ):
                print('Fingerprints do not match, try again')
                continue

            break

        except Exception as e:
            print("Error processing fingerprint: " + str(e))
            print("Try again")
            continue

    try:
        f.createTemplate()
        positionNumber = f.storeTemplate()
        print('Fingerprint enrolled successfully!')

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)

if __name__ == "__main__":
    main()