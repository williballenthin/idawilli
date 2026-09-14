"""Plugin settings declared in ``ida-plugin.json`` and read through ida-settings."""

from pathlib import Path

PLUGIN_NAME = "vtloader"
VT_FORMAT_NAME = "vtloader"
VT_HASH_PROMPT = "SHA-256 of the file on VirusTotal"
VT_API_KEY_SETTING = "vt_api_key"


class SettingsError(Exception):
    pass


class ApiKeyMissingError(SettingsError):
    pass


def get_vt_api_key() -> str:
    """The VirusTotal API key from the plugin settings.

    Raises:
        ApiKeyMissingError: no key is configured, or it is empty.
        SettingsError: the ida-settings package is missing, the plugin is not
            installed under ``$IDAUSR/plugins`` where ida-settings looks for it, or
            the settings cannot be read at all.
    """
    try:
        import ida_settings
    except ImportError as e:
        raise SettingsError(
            f"the ida-settings package is not available to IDA's Python ({e}); "
            "reinstall the plugin with hcli to install its Python dependencies"
        ) from e
    try:
        key = ida_settings.PluginSettings(PLUGIN_NAME).get_setting(VT_API_KEY_SETTING)
    except KeyError:
        key = None
    except Exception as e:
        raise SettingsError(
            f"cannot read the {VT_API_KEY_SETTING} setting of the {PLUGIN_NAME} plugin: {e}"
        ) from e
    if not isinstance(key, str) or not key.strip():
        raise ApiKeyMissingError(
            "no VirusTotal API key is set in the vtloader plugin settings"
        )
    return key.strip()


def get_vt_database_dir() -> Path:
    """The directory that receives databases of files fetched from VirusTotal."""
    return Path.home() / "Downloads"
