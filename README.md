# tls-certificates-interface

## Description

This project contains libraries for the tls-certificates relationship. It contains both the 
provider and the requirer side of them.

> Note: The charm located here is a placeholder charm.

## Usage
From a charm directory where the `tls-certificates-interface` library is needed:

```bash
charmcraft fetch-lib charms.tls_certificates_interface.v0.tls_certificates
```

## Relations

```bash
juju relate <tls-certificates provider charm> <tls-certificates requirer charm>
```
