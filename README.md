Generate self-signed certificates non-interactively.

The generated certificate will be printed to standard out.

To build for Linux, using Docker:

```
make bin/snakeoil
```

To run:

```
# bin/snakeoil --help
usage: snakeoil --key=KEY [<flags>]

Flags:
  --help           Show context-sensitive help (also try --help-long and --help-man).
  --key=KEY        RSA private key
  --CN=CN          The fully qualified domain name used for DNS lookups of your server
  --O=O ...        Name of organization
  --OU=OU ...      Division or department in organization
  --C=C ...        Two letter country code
  --ST=ST ...      State, province or county
  --L=L ...        City
  --expires=8760h  Expiry
```

For example:

```
bin/snakeoil --key=/opt/private.key --CN=domain.com --O=SomeCorp > certificate.pem
```
