# `zeratool_lib` 🗡️

## Description

`zeratool_lib` is a fork of [Zeratool](https://github.com/ChrisTheCoolHut/Zeratool). Its purpose is to port the CLI tool into a **Python 3 library** for **exploiting executables on the local machine**.

> **Notice**: `zeratool_lib` is not a rewrite of Zeratool. It still uses the exploitation logic implemented by Zeratool's developers, but it has the modifications stated in the next section.

### Differences Compared to the Parent Repository

* The CLI was replaced with a unique function that can be called by programs which import the library. All relevant parameters are exposed as parameters of this function.
* All remote exploitation logic was removed.
* The exploit is returned by the main function.
* `libpwnable` is no longer an input stream. The only ones supported now are `stdin` and arguments.

## Setup

Make sure `uv` is installed:

```console
uv --version
```

Create a virtual environment using Python 3.12:

```console
uv venv --python 3.12
```

Install the required dependencies based on `pyproject.toml` and `uv.lock`:

```console
uv sync
```

## Usage

```python
from zeratool_lib import exploit, ZeratoolInputStreams

payload, outcome = exploit(
    "key-manager.elf",
    input_stream=ZeratoolInputStreams.STDIN,
    overflow_only=True,
    win_functions=["get_private_key"],
    leak_format="(.*)BEGIN PRIVATE KEY(.*)"
)
```
