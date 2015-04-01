# totp-tool
A python tool to generate 2fa codes from your command line.  Keys are stored in an encrypted json file.  Tool supports encryption / decryption of totp keys.

Usage:

Create encrypted JSON file (use totp.json.example as an example of json format)

	./totp.py encrypt infile [outfile]  (default is totp.json.enc)

Decrypt json file:

	./totp.py decrypt infile [outfile] (default is to print to stdout)

Generate 2fa codes:

	./totp.py list


TIP: Edit and place the included wrapper example file into a directory in your path to facilitate easier usage from any terminal window.
