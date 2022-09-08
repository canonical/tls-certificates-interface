# tls-certificates-interface

## Description

This project contains libraries for the tls-certificates relationship. It contains both the 
provider and the requirer side of the relation.

> **Warning**: The charm located here is a placeholder charm and shouldn't be deployed.

## Usage

From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v1.tls_certificates
```

Add the following libraries to the charm's `requirements.txt` file:
- `jsonschema==4.15.0`
- `cryptography==38.0.0`

Add the following section to the charm's `charmcraft.yaml` file:
```yaml
parts:
  charm:
    build-packages:
      - libffi-dev
      - libssl-dev
      - rustc
      - cargo
```

## Relations

```bash
juju relate <tls-certificates provider charm> <tls-certificates requirer charm>
```
