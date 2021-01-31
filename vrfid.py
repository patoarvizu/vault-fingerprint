#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import click
import time
from pirc522 import RFID

@click.group()
@click.option('-address', default='http://127.0.0.1:8200')
@click.pass_context
def main(ctx, address):
    ctx.obj = {
        'address': address
    }
    pass

@main.command()
@click.option('-key-shares', default=5, type=int)
@click.pass_context
def init(ctx, key_shares):
    address = ctx.obj['address']
    rdr = RFID()
    util = rdr.util()
    try:
        payload = {
            'secret_shares': key_shares,
            'secret_threshold': key_shares,
            'stored_shares': key_shares,
            'recovery_shares': key_shares,
            'recovery_threshold': key_shares
        }
        request_result = requests.put(address + '/v1/sys/init', data=json.dumps(payload))
        result_json = json.loads(request_result.text)
        block = 4
        for unseal_key in result_json["keys"]:
            print("Unseal key: {}".format(unseal_key))
            print("Place tag to save it")
            rdr.wait_for_tag()
            (error, tag_type) = rdr.request()
            if not error:
                (error, uid) = rdr.anticoll()
                if not error:
                    print("Tag detected with UID: " + str(uid[0])+"-"+str(uid[1])+"-"+str(uid[2])+"-"+str(uid[3]))
                    util.set_tag(uid)
                    util.auth(rdr.auth_a, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                    error = False
                    for s in range(5):
                        if (block + 1) % 4 == 0:
                            block += 1
                        util.do_auth(block)
                        data = [0] * 16
                        rdr.write(block, data)
                        for i, d in enumerate(bytes(unseal_key[s*16:(s+1)*16].encode())):
                            data[i] = d
                        error = rdr.write(block, data)
                        if error:
                            break
                        block += 1
                    if error:
                        print("Error writing to tag!")
                        break
                    print("Tag saved!")
                    print("Remove tag")
                else:
                    print("Error calling anticoll()")
                    break
            else:
                print(error)
                print("Error calling request()")
                break
            time.sleep(2)

        print("Root token: " + result_json["root_token"])

    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)
    finally:
        rdr.cleanup()
        util.deauth()

@main.command()
@click.pass_context
def unseal(ctx):
    address = ctx.obj['address']
    rdr = RFID()
    util = rdr.util()
    try:
        while True:
            print("Place next tag")
            rdr.wait_for_tag()
            (error, tag_type) = rdr.request()
            if not error:
                (error, uid) = rdr.anticoll()
                if not error:
                    print("Tag detected with UID: " + str(uid[0])+"-"+str(uid[1])+"-"+str(uid[2])+"-"+str(uid[3]))
                    util.set_tag(uid)
                    util.auth(rdr.auth_a, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                    block = 4
                    key = ''
                    error = False
                    for s in range(5):
                        if (block + 1) % 4 == 0:
                            block += 1
                        util.do_auth(block)
                        error, data = rdr.read(block)
                        if error:
                            break
                        else:
                            key += bytes(data).decode()
                        block += 1
                    if error:
                        print("Error, try again!")
                        time.sleep(2)
                        continue
                    payload = {
                        'key': key.rstrip('\x00')
                    }
                    progress = json.loads(requests.put(address + '/v1/sys/unseal', data=json.dumps(payload)).text)
                    if not progress["sealed"]:
                        print("Vault is unsealed!")
                        break
            time.sleep(2)
    except Exception as e:
        print('Operation failed!')
        print('Exception message: ' + str(e))
        exit(1)
    except KeyboardInterrupt:
        print('KeyboardInterrupt')
        exit(0)
    finally:
        rdr.cleanup()
        util.deauth()

@main.command()
@click.pass_context
def generate_root(ctx):
    address = ctx.obj['address']
    rdr = RFID()
    util = rdr.util()
    try:
        
        attempt_result = requests.put(address + '/v1/sys/generate-root/attempt')
        attempt_object = json.loads(attempt_result.text)
        nonce = attempt_object["nonce"]
        progress = None
        for unseal_key in unseal_keys_object["encrypted_keys"]:
            payload = {
                'key': key,
                'nonce': nonce
            }
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

if __name__ == "__main__":
    main()