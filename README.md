# tpm-sign-verify

This is a proof of concept signature signing with TPM hardware. Beware,
very rough edges. These are the steps I preformed to run it:

* Hardware: ThinkPad T430s
* Distribution: Fedora 21

## License, contact

This code is in the public domain. See https://creativecommons.org/publicdomain/zero/1.0/ for more info.

Written by Noa Resare (noa@spotify.com) as part of a hackday project in April 2015.

## Steps

* Make sure you have the following packages installed: `gnutls-utils gnutls-devel tpm-tools gcc make`

* Make sure your PTM is wiped clean. To do this, turn off the computer (restart doesn't work for me), boot into BIOS settings, Security -> Security chip -> Clear. Save changes. Reboot.

* start the tcsd TPM comms daemon as root: `sudo systemctl start tcsd.service`

* Take ownership of TPM with `tpm_takeownership` (I use the SRK password 'a')

* Generate an RSA keypair on the TPM with this: `tpmtool --generate-rsa --bits 2048 --register --user`

* Export the public part of the keypair to a file named pubkey.pem: `tpmtool --pubkey "tpmkey:uuid=5014ce3f-aab4-4ab6-83ac-572b7bd33654;storage=user" --outfile pubkey.pem` (your uuid will differ, use the output of `tpmtool --list`)

* Adjust the TPM_KEY_URL define in the top of sign.c to match your key

* Build the programs with `make`

* Run `./sign`. This will generate a random challenge.bin and corresponding signature signature.bin using the TPM private key

* Run `./verify` to verify that the contents that signature.bin is a valid signature of challenge.bin using pubkey.pem
