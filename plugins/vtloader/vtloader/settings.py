"""Plugin settings declared in ``ida-plugin.json`` and read through ida-settings."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PLUGIN_NAME = "vtloader"
VT_FORMAT_NAME = "vtloader"
VT_HASH_PROMPT = "SHA-256 of the file on VirusTotal"
VT_API_KEY_SETTING = "vt_api_key"


class SettingsError(Exception):
    pass


class ApiKeyMissingError(SettingsError):
    pass


def get_setting(key: str) -> str | None:
    """Read one string setting of this plugin, or None when it is unset or empty.

    Raises:
        SettingsError: the ida-settings package is missing, or the plugin is not
            installed under ``$IDAUSR/plugins`` where ida-settings looks for it.
    """
    try:
        import ida_settings
    except ImportError as e:
        raise SettingsError(
            f"the ida-settings package is not available to IDA's Python ({e}); "
            "reinstall the plugin with hcli to install its Python dependencies"
        ) from e
    try:
        value = ida_settings.PluginSettings(PLUGIN_NAME).get_setting(key)
    except KeyError:
        return None
    except Exception as e:
        raise SettingsError(
            f"cannot read the {key} setting of the {PLUGIN_NAME} plugin: {e}"
        ) from e
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def get_vt_api_key() -> str:
    """The VirusTotal API key from the plugin settings.

    Raises:
        ApiKeyMissingError: no key is configured.
        SettingsError: the settings cannot be read at all.
    """
    key = get_setting(VT_API_KEY_SETTING)
    if key is None:
        raise ApiKeyMissingError(
            "no VirusTotal API key is set in the vtloader plugin settings"
        )
    return key


def get_vt_database_dir() -> Path:
    """The directory that receives databases of files fetched from VirusTotal."""
    return Path.home() / "Downloads"
