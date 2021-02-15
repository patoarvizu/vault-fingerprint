# HashiTalks 2021 demo

## IMPORTANT

This is a demo for learning purposes only, and as a hands-on lab for my HashiTalks 2021 presentation.

- **Do NOT do this in production or on any environment you can’t afford to lose.**
- **Do NOT rely on this.**
- **This is NOT an official HashiCorp tool.**
- **There is NO support for this.**

## Prerequisites

- A Raspberry Pi running Raspberry Pi OS. Other compatible Linux operating systems or 40-pin GPIO boards might work as well. The demo during the talk was done using a Raspberry Pi 3B.
  - Setting up the Raspberry Pi, as well as the materials involved are out of the scope of this tutorial, but you can find a guide [here](https://www.raspberrypi.org/documentation/configuration/wireless/headless.md), and buy most of the materials you need on [Adafruit](https://www.adafruit.com/).
- For the fingerprint demo:
  - A fingerprint scanner, like [this](https://www.adafruit.com/product/4690).
  - An USB to TTL adapter, like [this](https://www.amazon.com/gp/product/B075N82CDL).
- For the RFID demo:
  - An RFID scanner, like [this](https://www.amazon.com/gp/product/B07KGBJ9VG).
  - A set of RFID cards or fobs, like [these](https://www.amazon.com/YARONGTECH-13-56MHZ-MIFARE-Classic-control/dp/B01FR6NN6Y). (Make sure they work with RC522 or PN532 scanners. The scanner above cannot read other card types like NTAGs.)
- Install [Vault](https://www.vaultproject.io/downloads) on the Pi. (Note: depending on your Pi and operating system, you may need to get either the 32-bit or 64-bit version. If you're not sure, it's most likely the 32-bit one.)
- Install `python3` on the Pi.

## Steps

- This tutorial assumes you're running with the default `pi` user.
- Run `sudo adduser pi gpio` so you can run the scripts without requiring `sudo`.
- Clone this repo at the home directory for the `pi` user (`/home/pi`). and `cd` into it, i.e. `cd /home/pi/vault-fingerprint`.
- Run `make install-vault-svc` to install a Systemd unit file for Vault.
- Run `export VAULT_ADDR=http://127.0.0.1:8200/`.
- Run `make install-requirements`.

### Fingerprint demo

- Run `make start`.
- Run `./vfp.py enroll` and follow the prompts to enroll a new fingerprint.
  - This is the fingerprint that will be allowed to initialize, and unseal Vault. You can enroll as many as 300 fingerprints.
- Run `./vfp.py init` and follow the instructions. Use the finger you enrolled in the previous step.
- After initializing successfully, you'll see the root token being printed on screen, as well as the two files holding the unseal keys. Copy the root token and set it to the `VAULT_TOKEN` environment variable.
- Run `vault status` and confirm that Vault is now initialized, but not yet unsealed.
- Run `./vfp.py unseal` and follow the instructions, using again the same fingerprint.
- Try the following to validate that Vault is working as expected (assuming `VAULT_TOKEN` is set to the root token shown earlier):
  - `vault secrets enable kv -path=secret`
  - `vault kv put secret/foo bar=baz`
  - `vault kv get secret/foo`
- Run `make restart` to force Vault to get sealed. Run `vault status` to confirm.
- Run `./vfp.py unseal` to go through the unseal process again, using the same finger as before.
- Run `vault kv get secret/foo` to validate that Vault is working as expected.

### RFID demo

- Run `make wipe` to clean the data from the previous demo. Confirm with `vault status` that Vault is uninitialized and unsealed. Also, run `unset VAULT_TOKEN` to clean out the previous token.
- Run `./vrfid.py init` to initialize Vault and start the process of storing the unseal keys on the RFID cards.
  - Note: by default, the script expects 5 cards, but you can change that by adding `-key-shares 3` or `-key-shares 1` if you have less than 5 cards.
- After initializing successfully, you'll see the root token being printed on screen, as well as the two files holding the unseal keys. Copy the root token and set it to the `VAULT_TOKEN` environment variable.
- Run `./vrfid.py unseal`, and follow the prompts on the screen. You'll be asked to scan the number of `-key-shares` you specified on the previous step (or the default of 5), one at a time. Note that the order **doesn't** matter, you can scan the cards in a different order than you use to initialize.
- Try the following to validate that Vault is working as expected (assuming `VAULT_TOKEN` is set to the root token shown earlier):
  - `vault secrets enable kv -path=secret`
  - `vault kv put secret/foo bar=baz`
  - `vault kv get secret/foo`
- Run `make restart` to force Vault to get sealed. Run `vault status` to confirm.
- Run `./vrfid.py unseal` to go through the unseal process again, using the same finger as before.
- Run `vault kv get secret/foo` to validate that Vault is working as expected.