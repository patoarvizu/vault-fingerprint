#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pyfingerprint.pyfingerprint import PyFingerprint
from cryptography.fernet import Fernet
import requests
import json
import hashlib
import click
import time

FINGERPRINT_CHARBUFFER1 = 0x01
FINGERPRINT_CHARBUFFER2 = 0x02

def __initSensor(device):
    try:
        fingerprint_device = PyFingerprint(device)
        if ( fingerprint_device.verifyPassword() == False ):
            raise ValueError('The given fingerprint sensor password is wrong!')

    except Exception as e:
        print('The fingerprint sensor could not be initialized!')
        print('Exception message: ' + str(e))
        exit(1)

    return fingerprint_device

def __readUntilFound(fingerprint_device):
    while True:
        try:
            print('Waiting for finger...')
            while ( fingerprint_device.readImage() == False ):
                pass

            fingerprint_device.convertImage()
            result = fingerprint_device.searchTemplate()
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
@click.option('-address', default='http://127.0.0.1:8200')
@click.option('-encryption-key-file', default="fingerprint-encryption.key")
@click.option('-encryption-init-output-file', default="encrypted-init-output.json")
@click.option('-device', default="/dev/ttyUSB0")
@click.pass_context
def main(ctx, address, encryption_key_file, encryption_init_output_file, device):
    ctx.obj = {
        'address': address,
        'encryption_key_file': encryption_key_file,
        'encryption_init_output_file': encryption_init_output_file,
        'device': device
    }
    pass

@main.command()
@click.option('-key-shares', default=5, type=int)
@click.pass_context
def init(ctx, key_shares):
    address = ctx.obj['address']
    encryption_key_file = ctx.obj['encryption_key_file']
    encryption_init_output_file = ctx.obj['encryption_init_output_file']
    device = ctx.obj['device']
    fingerprint_device = __initSensor(device)
    __readUntilFound(fingerprint_device)

    try:
        key = Fernet.generate_key()
        fernet = Fernet(key)
        payload = { 'secret_shares': key_shares, 'secret_threshold': key_shares, 'stored_shares': key_shares, 'recovery_shares': key_shares, 'recovery_threshold': key_shares }
        request_result = requests.put(address + '/v1/sys/init', data=json.dumps(payload))
        result_json = json.loads(request_result.text)
        encrypted_init_output = {}
        encrypted_keys = []
        for unseal_key in result_json["keys"]:
            encrypted_keys.append(fernet.encrypt(unseal_key.encode()).decode())

        encrypted_init_output['encrypted_keys'] = encrypted_keys
        unseal_keys_file = open(encryption_init_output_file, "w")
        unseal_keys_file.write(json.dumps(encrypted_init_output))
        unseal_keys_file.close()
        key_file = open(encryption_key_file, "w")
        key_file.write(key.decode())
        key_file.close()

        print("Root token: " + result_json["root_token"])
        print("Encrypted unseal keys are in " + encryption_init_output_file)
        print("Encryption key for unseal keys is in " + encryption_key_file)

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)

@main.command()
@click.pass_context
def unseal(ctx):
    address = ctx.obj['address']
    encryption_key_file = ctx.obj['encryption_key_file']
    encryption_init_output_file = ctx.obj['encryption_init_output_file']
    device = ctx.obj['device']
    fingerprint_device = __initSensor(device)
    __readUntilFound(fingerprint_device)

    try:
        key_file = open(encryption_key_file, "r")
        fernet = Fernet(key_file.read())
        unseal_keys_file = open(encryption_init_output_file, "r")
        unseal_keys_object = json.loads(unseal_keys_file.read())
        for unseal_key in unseal_keys_object["encrypted_keys"]:
            payload = { 'key': fernet.decrypt(unseal_key.encode()).decode() }
            requests.put(address + '/v1/sys/unseal', data=json.dumps(payload))

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)

@main.command()
@click.pass_context
def generate_root(ctx):
    address = ctx.obj['address']
    encryption_key_file = ctx.obj['encryption_key_file']
    encryption_init_output_file = ctx.obj['encryption_init_output_file']
    device = ctx.obj['device']
    fingerprint_device = __initSensor(device)
    __readUntilFound(fingerprint_device)
    try:
        key_file = open(encryption_key_file, "r")
        fernet = Fernet(key_file.read())
        unseal_keys_file = open(encryption_init_output_file, "r")
        unseal_keys_object = json.loads(unseal_keys_file.read())
        attempt_result = requests.put(address + '/v1/sys/generate-root/attempt')
        attempt_object = json.loads(attempt_result.text)
        nonce = attempt_object["nonce"]
        progress = None
        for unseal_key in unseal_keys_object["encrypted_keys"]:
            payload = { 'key': fernet.decrypt(unseal_key.encode()).decode(), 'nonce': nonce }
            update_result = requests.put(address + '/v1/sys/generate-root/update', data=json.dumps(payload))
            progress = json.loads(update_result.text)
            if progress["complete"] == True:
                break

        print("Root token generation complete, to get the decoded token run:")
        print("  vault operator generate-root -decode=" + progress["encoded_root_token"] + " -otp=" + attempt_object["otp"])

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        print('The root token generation process will be reset')
        requests.delete(address + '/v1/sys/generate-root/attempt')
        exit(1)

@main.command()
@click.pass_context
def enroll(ctx):
    device = ctx.obj['device']
    fingerprint_device = __initSensor(device)
    while True:
        try:
            print('Waiting for finger...')
            while ( fingerprint_device.readImage() == False ):
                pass

            fingerprint_device.convertImage(FINGERPRINT_CHARBUFFER1)
            result = fingerprint_device.searchTemplate()
            positionNumber = result[0]
            if ( positionNumber >= 0 ):
                print('Fingerprint already exists at position #' + str(positionNumber))
                exit(0)

            print('Remove finger...')
            time.sleep(2)
            print('Place same finger again...')
            while ( fingerprint_device.readImage() == False ):
                pass

            fingerprint_device.convertImage(FINGERPRINT_CHARBUFFER2)
            if ( fingerprint_device.compareCharacteristics() == 0 ):
                print('Fingerprints do not match, try again')
                continue

            break

        except Exception as e:
            print("Error processing fingerprint: " + str(e))
            print("Try again")
            continue

    try:
        fingerprint_device.createTemplate()
        positionNumber = fingerprint_device.storeTemplate()
        print('Fingerprint enrolled successfully!')

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)

if __name__ == "__main__":
    main()