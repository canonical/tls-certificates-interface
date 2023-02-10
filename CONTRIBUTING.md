# tls-certificates-interface

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate

## Testing

Testing for this project is done using `tox`. You can run the various tests like so:

Each major version of the interface is tested independently. For example for `v1`:

```shell
tox -e lint-v1      # code style
tox -e static-v1    # static analysis
tox -e unit-v1      # unit tests
```
