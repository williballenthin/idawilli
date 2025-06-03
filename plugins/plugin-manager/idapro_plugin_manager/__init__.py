import sys
import logging
import platform

if sys.version_info < (3, 10):
    # once we drop support for Python 3.9,
    # remove this and the dependency on `importlib_metadata`.
    import importlib_metadata
    import importlib_resources
else:
    import importlib.metadata as importlib_metadata
    import importlib.resources as importlib_resources


logger = logging.getLogger(__name__)


def get_current_target_triple() -> str:
    """
    Generates the current target triple based on the OS and architecture.
    The format aims to be similar to "arch-vendor-os".

    Supports:
    - OS: Linux, macOS (Darwin), Windows
    - Architectures: x86_64 (amd64), aarch64 (arm64)

    Returns:
        str: The target triple string (e.g., "aarch64-apple-darwin", "x86_64-unknown-linux", "x86_64-pc-windows").

    Raises:
        ValueError: If the OS or architecture is not supported or recognized.
    """
    system_name = platform.system()
    machine_name = platform.machine()

    arch = ""
    machine_lower = machine_name.lower()
    if machine_lower in ("amd64", "x86_64"):
        arch = "x86_64"
    elif machine_lower in ("arm64", "aarch64"):
        arch = "aarch64"
    else:
        raise ValueError(f"Unsupported architecture: {machine_name}")

    os_vendor_part = ""
    if system_name == "Darwin":
        os_vendor_part = "apple-darwin"
    elif system_name == "Linux":
        os_vendor_part = "unknown-linux"
    elif system_name == "Windows":
        os_vendor_part = "pc-windows"
    else:
        raise ValueError(f"Unsupported operating system: {system_name}")

    return f"{arch}-{os_vendor_part}"


def install():
    """
    Load all registered IDA Pro plugins.

    Plugins are registered by adding an entry point to the `idapro.plugins` group,
    which is done in a Python package's setuptools or pyproject.toml configuration.

    For example, consider a simple plugin package like:

        basic-ida-plugin/
        ├── hello.py
        └── pyproject.toml

    with the pyproject.toml contents:

        [project]
        name = "basic-ida-plugin"
        ...

        [project.entry-points.'idapro.plugins']
        idapython = 'hello'

    and hello.py contents:

        import idaapi

        class hello_plugmod_t(idaapi.plugmod_t):
            def run(self, arg):
                print("Hello world! (py)")
                return 0

        class hello_plugin_t(idaapi.plugin_t):
            flags = idaapi.PLUGIN_UNL | idaapi.PLUGIN_MULTI
            comment = "This is a comment"
            help = "This is help"
            wanted_name = "Hello Python plugin"
            wanted_hotkey = "Alt-F8"

            def init(self):
                print("hello from init")
                return hello_plugmod_t()

        def PLUGIN_ENTRY():
            return hello_plugin_t()
    """
    # keep this import lazy so the top level module can be imported
    # without being inside IDA (such as in tests).
    import ida_loader

    current_target = get_current_target_triple()
    logger.info("current target: %s", current_target)
    plugins = list(importlib_metadata.entry_points(group="idapro.plugins"))

    for plugin in plugins:
        # the name of the plugin, from the project name, like `basic-ida-plugin` here:
        #
        #     [project]
        #     name = "basic-ida-plugin"
        if not plugin.dist:
            logger.warning("missing dist: %s", plugin)
            continue
        name = plugin.dist.name

        # `plugin.name` is the key of an entry point item like `idapython` here:
        #
        #     [project.entry-points.'idapro.plugins']
        #     idapython = 'hello'
        target = plugin.name

        if target == "idapython":
            # load an IDAPython-based plugin
            logger.debug("loading Python plugin: %s", name)

            # Import the Python module that contains the plugin.
            # This is a standard Python importlib-level operation to load the code.
            # It invokes anything at the top level of the module, but
            #  but it doesn't call `PLUGIN_ENTRY`, which is handled by `load_plugin` below.
            try:
                mod = plugin.load()
            except ImportError as e:
                logger.warning("failed to load: %s: %s", name, e, exc_info=True)
                continue

            # Path to the plugin, which is typically somewhere in the site-packages directory.
            # *Technically* a Python module doesn't have to be backed by a file, but this is rare,
            #  so let's assume/require this for the plugin manager.
            path = mod.__file__

            # Now load the plugin using IDA's infrastructure (invoking `PLUGIN_ENTRY`).
            try:
                logger.debug("loading_plugin: %s", str(path))
                ida_loader.load_plugin(path)
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("failed to load_plugin: %s: %s", name, e, exc_info=True)
                continue

            logger.info("loaded: %s", name)

        elif target == current_target:
            # load a native plugin
            logger.debug("loading native plugin: %s", name)

            # This is like "native_ida_plugin" for the spec "native_ida_plugin:mysample"
            module_path = importlib_resources.files(plugin.module)

            extension: str
            if target.endswith("-darwin"):
                extension = ".dylib"
            elif target.endswith("-linux"):
                extension = ".so"
            elif target.endswith("-windows"):
                extension = ".dll"
            else:
                logger.warning("unexpected target: %s", target)
                continue

            # This is like "mysample" for the spec "native_ida_plugin:mysample"
            plugin_file_name = plugin.attr

            # Like: "native_ida_plugin/mysample.so"
            plugin_path = str(module_path / plugin_file_name) + extension

            # Load the plugin using IDA's infrastructure (invoking `PLUGIN_ENTRY`).
            try:
                logger.debug("loading_plugin: %s", plugin_path)
                ida_loader.load_plugin(plugin_path)
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("failed to load_plugin: %s: %s", name, e, exc_info=True)
                continue

            logger.info("loaded: %s", name)

        else:
            logger.warning("unexpected target: %s", target)
