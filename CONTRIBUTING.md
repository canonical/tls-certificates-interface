# Contributing

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

This project uses `uv`. You can install it on Ubuntu with:

```shell
sudo snap install --classic astral-uv
```

You can create an environment for development with `uv`:

```shell
uv sync
```

## Testing

This project uses `tox` for managing test environments. It can be installed
with:

```shell
uv tool install tox --with tox-uv
```

There are some pre-configured environments that can be used for linting
and formatting code when you're preparing contributions to the charm:

```shell
tox -e format        # update your code according to linting rules
tox -e lint          # code style
tox -e unit          # unit tests
tox                      # runs 'format', 'lint', and 'unit' environments
```

## Integration Tests

To run the integration tests, you need to install the right dependency group
for the version of Juju you want to test:

```shell
uv sync --group test_juju_3
# OR
uv sync --group test_juju_2  # Only supported for the version 2 of the library
```

You can then run the integration tests for the version of the library you
want to test:

```shell
tox -e integration-v4
# OR
tox -e integration-v3
# OR
tox -e integration-v2-juju-3
# OR
tox -e integration-v2-juju-2
```
