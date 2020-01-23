Generate self-signed certificates with SANs non-interactively.

To build:

```
make bin/snakeoil
```

To run:

```
# bin/snakeoil --help
usage: snakeoil --key=KEY [<flags>] <PATH>

Flags:
  --help                     Show context-sensitive help (also try --help-long and --help-man).
  --key=KEY                  RSA private key
  --wednesday-expiry         Round the expiry to the nearest Wednesday lunchtime
  --CN=CN                    The fully qualified domain name used for DNS lookups of your server
  --O=O ...                  Name of organization
  --OU=OU ...                Division or department in organization
  --C=C ...                  Two letter country code
  --ST=ST ...                State, province or county
  --L=L ...                  City
  --expires=8760h            Expiry
  --dns=DNS ...              DNS names
  --ip=IP ...                Address to add to the SAN
  --interface=INTERFACE ...  Interface to scan for addresses

Args:
  <PATH>  Path to write certificate to
```

For example:

```
bin/snakeoil --key=/opt/private.key --CN=domain.com --O=SomeCorp certificate.pem
```
