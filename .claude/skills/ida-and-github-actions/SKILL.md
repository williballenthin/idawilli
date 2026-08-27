---
name: ida-and-github-actions
description: Use best practices to configure a GitHub Action workflow to use IDA, idalib, and/or HCLI.
---


Workflows should generally use this order, because some of the steps create environments that subsequent steps depend on.

# Python Installation

Use `astral-sh/setup-uv` with `python-version:`.
Use hash pinning with a comment indicating the version.

# HCLI Installation

Unless the step is testing HCLI itself, use uv to invoke HCLI:

    uv run --with ida-hcli hcli

# IDA Installation

Use the short tag format:

    ida-pro:latest

When multiple versions are IDA are used, then use a specific tag, like `ida-pro:9.4`. Otherwise, use `latest`.

Always provide the following flags: --license-id ${IDA_LICENSE_ID} --install-dir="${{ runner.temp }}/app/ida" --accept-eula --set-default --yes

Provide the license ID and HCLI API key as environment variables:

```yml
    env:
        HCLI_API_KEY: ${{ secrets.HCLI_API_KEY }}
        IDA_LICENSE_ID: ${{ secrets.IDA_LICENSE_ID }}
```

# venv creation

## IDA's Python environment

While IDA comes bundled with Python, users can and should provide their own Python installation, specified with `idapyswitch`.
And, it is strongly recommended to use a virtual environment, because this avoids dependency conflicts and issues with "externally managed" environments.
Use `IDAPYTHON_VENV_EXECUTABLE` rather than `VIRTUAL_ENV` to signal the virtual environment to IDA (without interfering with other tools that use `VIRTUAL_ENV`).

For IDA plugins that are installed and tested in CI (you should see `hcli plugin install...`), create a venv for IDA.
Use `--seed` so that `pip` is available in the venv; `hcli plugin install` uses pip to install plugin Python dependencies.

    uv venv --seed $HOME/.idapro/venv

Register the interpreter with IDA:

    ${{ runner.temp }}/app/ida/${{ matrix.ida.idapyswitch }} --force-path $(uv run --python $HOME/.idapro/venv python -c 'import sys,sysconfig,pathlib;print(__import__("_winapi").GetModuleFileName(sys.dllhandle) if sys.platform=="win32" else next(pathlib.Path(sysconfig.get_config_var("LIBDIR")).glob("libpython*")))')

This causes IDA to use the specific version of Python, which is important when Python loads native libraries (Pydantic, SSL, etc.).

When subsequent steps start IDA or HCLI, they should point `IDAPYTHON_VENV_EXECUTABLE` to the virtual environment's Python interpreter.
Use `uv python find` to resolve the path cross-platform (avoids platform-specific `bin/python3` vs `Scripts/python.exe`):

```yml
    env:
        IDAPYTHON_VENV_EXECUTABLE: $(uv python find $HOME/.idapro/venv)
```

On Windows, the path must use native separators: wrap with `cygpath -w` in bash steps.

This causes IDA to use the virtual environment for Python, giving access to the libraries installed there.
Unfortunately, both idapyswitch and the virtual environment registration are required.

## Python programs using idalib

For Python programs that use IDA as a library (idalib), create and activate a venv using uv: 

    uv sync --no-sources --extra dev --extra test

The program will this environment's Python intepreter and virtual environment. When it loads IDA via idalib, IDA will also use this environment, so no additional setup is required.

Note that it is possible that an program may rely on idalib and expect IDA to run plugins, such as to load new file formats.
In this case, the setup may be complicated: all the Python dependencies of the IDA plugins must be available in the *program's* virtual environment.
There's not an easy way to programmatically do this today; you should hardcode the installation of the deps into to virtual environment setup.
HCLI should probably grow a command to do this.

# idalib

For programs that use idalib, they need the idapro or ida-domain Python packages in their virtual environment, which they should have in their `pyproject.toml` file.


# Example workflow

```yml
    tests:
      name: IDA ${{ matrix.ida.version}} on ${{ matrix.ida.os }}/py${{ matrix.python-version }}
      runs-on: ${{ matrix.ida.os }}
      strategy:
        fail-fast: false
        matrix:
          python-version: ["3.10", "3.14"]
          ida:
            - version: "9.4"
              os: ubuntu-latest
              idapyswitch: "/idapyswitch"
              
            - version: "latest"
              os: ubuntu-latest
              idapyswitch: "/idapyswitch"
              
            - version: "latest"
              os: macos-latest
              idapyswitch: "/Contents/MacOS/idapyswitch"
              
            - version: "latest"
              os: windows-latest
              idapyswitch: "/idapyswitch.exe"
      steps:
        - name: Checkout
          uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
          with:
            fetch-depth: 0
            persist-credentials: false

        - name: Setup uv
          uses: astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9 # v9.0.0
          with:
            enable-cache: true
            cache-dependency-glob: "uv.lock"
            version: "0.12.6"
            python-version: ${{ matrix.python-version }}
            
        - name: Install IDA ${{ matrix.ida.version }}
          shell: bash
          run: |
            uv run --with ida-hcli hcli \
              ida install \
              --download-id "ida-pro:${{ matrix.ida.version }}" \
              --license-id "${IDA_LICENSE_ID}" \
              --install-dir="${{ runner.temp }}/app/ida" \
              --accept-eula \
              --set-default \
              --yes
          env:
            HCLI_API_KEY: ${{ secrets.HCLI_API_KEY }}
            IDA_LICENSE_ID: ${{ secrets.IDA_LICENSE_ID }}
            
        # This is the environment that IDA will use when run as a program (ida.exe, idat.exe, etc.),
        #  including where plugin dependencies will be installed.
        # This should be set before HCLI installs plugins.
        - name: Create venv for IDA
          run: uv venv --seed $HOME/.idapro/venv

        # Register the specific Python interpreter with IDA, so that native Python extensions load correctly.
        - name: Register Python interpreter with IDA
          run: |
            ${{ runner.temp }}/app/ida/${{ matrix.ida.idapyswitch }} \
              --force-path $( \
                uv run --python $HOME/.idapro/venv python -c \
                  'import sys,sysconfig,pathlib;print(__import__("_winapi").GetModuleFileName(sys.dllhandle) if sys.platform=="win32" else next(pathlib.Path(sysconfig.get_config_var("LIBDIR")).glob("libpython*")))' \
              )
            
        - name: Set IDAPYTHON_VENV_EXECUTABLE
          shell: bash
          run: |
            VENV_PYTHON="$(uv python find "$HOME/.idapro/venv")"
            if [[ "$RUNNER_OS" == "Windows" ]]; then
              echo "IDAPYTHON_VENV_EXECUTABLE=$(cygpath -w "$VENV_PYTHON")" >> "$GITHUB_ENV"
            else
              echo "IDAPYTHON_VENV_EXECUTABLE=$VENV_PYTHON" >> "$GITHUB_ENV"
            fi

        - name: Install foo plugin to IDA
          run: uv run --with ida-hcli hcli plugin install foo

        - name: Create program environment
          run: uv sync --no-sources --extra dev --extra test
            
        - name: Run tests
          run: uv run pytest
```
