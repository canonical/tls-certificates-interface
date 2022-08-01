# tls-certificates-interface

## Description

This project contains libraries for the tls-certificates relationship. It contains both the 
provider and the requirer side of them.

> **Warning**: The charm located here is a placeholder charm and shouldn't be deployed.

## Usage

This library can be used by any charm requiring or providing this interface. From the charm's
root directory, run:

```bash
charmcraft fetch-lib charms.tls_certificates_interface.v1.tls_certificates
```

## Relations

```bash
juju relate <tls-certificates provider charm> <tls-certificates requirer charm>
```
