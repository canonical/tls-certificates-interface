# tls-certificates-interface

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements.txt

## Testing

### Unit tests

```bash
tox -e unit
```

### Static analysis

```bash
tox -e static
```

### Linting

```bash
tox -e lint
```