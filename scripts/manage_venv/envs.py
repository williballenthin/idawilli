# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

import logging
import os
import sys
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - module availability depends on IDA runtime
    import idaapi  # type: ignore
except ImportError:  # pragma: no cover - allows use from idalib or tests
    idaapi = None  # type: ignore


logger = logging.getLogger(__name__)


ENV_LOG_LEVEL = logging.WARNING
ENV_LOG_FORMAT = "%(message)s"


def configure_logging(level: Optional[int] = None) -> None:
    effective_level = level if level is not None else ENV_LOG_LEVEL
    logger.setLevel(effective_level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(ENV_LOG_FORMAT))
        logger.addHandler(handler)
    for handler in logger.handlers:
        handler.setLevel(effective_level)
    logger.propagate = False


configure_logging()


def detect_env(env: Optional[str] = None) -> bool:
    '''
    Detect and activate a Python environment.

    Strategy:
    1) If an environment is already active (VIRTUAL_ENV or CONDA_PREFIX), do nothing and return True.
    2) Try virtualenv with the provided env; on ValueError retry once with defaults (no args).
    3) Try conda with the provided env; on ValueError retry once with defaults (no args).

    Returns:
        True if an environment is (or becomes) active, False otherwise.
    '''
    logger.info("Detecting Python virtual environment...")

    # Normalize input: treat empty strings as None
    if env is not None and not str(env).strip():
        env = None

    # Fast path: already inside an environment
    already_active = os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX")
    if already_active:
        logger.info("Environment already active: %s", already_active)
        return True

    # Helper to try an activation once, then retry exactly once with defaults
    def _try_env(label, func, primary_kwargs, fallback_kwargs) -> bool:
        try:
            path = func(**primary_kwargs)
            logger.info("%s activated: %s", label, path)
            return True
        except ValueError as e:
            logger.info("%s: %s (retrying with defaults)", label, e)
            try:
                path = func(**fallback_kwargs)
                logger.info("%s activated on retry: %s", label, path)
                return True
            except ValueError as e2:
                logger.warning("%s retry failed: %s", label, e2)
                return False
        except Exception as e:
            # Defensive guard: unexpected errors shouldn't bring down detection
            logger.exception("%s unexpected error: %s", label, e)
            return False

    # 1) virtualenv: primary with provided env, fallback with defaults (no args)
    if _try_env(
        label="Virtualenv",
        func=activate_virtualenv_env,
        primary_kwargs={"virtualenv": env, "interactive": False},
        fallback_kwargs={},
    ):
        return True

    # 2) conda: primary with provided env, fallback with defaults (no args)
    if _try_env(
        label="Conda",
        func=activate_conda_env,
        primary_kwargs={"env": env, "interactive": False},
        fallback_kwargs={},
    ):
        return True

    logger.info("No Python environment activated.")
    return False


def _prompt_for_path(prompt: str, default: Path) -> Optional[str]:
    '''Ask the user for a filesystem path through the IDA UI.'''

    if idaapi is None:
        return None

    ask_new = getattr(idaapi, "ask_str", None)
    if callable(ask_new):
        return ask_new(str(default), 0, prompt)

    ask_old = getattr(idaapi, "askstr", None)
    if callable(ask_old):
        return ask_old(0, str(default), prompt)

    return None


def _normalize_env_path(candidate: Path, base_path: Path) -> Path:
    '''Return an absolute path for the given environment input.'''

    candidate = candidate.expanduser()
    return candidate if candidate.is_absolute() else base_path / candidate


def activate_virtualenv_env(
    virtualenv: Optional[str] = None,
    interactive: bool = True,
    base_dir: Optional[str] = None,
) -> str:
    '''Activate a virtualenv-based environment and return its absolute path.'''

    base_path = _resolve_base_path(base_dir)
    folder = Path("Scripts" if os.name == "nt" else "bin")

    env_path: Optional[Path] = None
    prompt_used = False

    if virtualenv:
        env_path = _normalize_env_path(Path(virtualenv), base_path)
    else:
        env_var = os.environ.get("VIRTUAL_ENV")
        if env_var:
            env_path = Path(env_var).expanduser()
        elif interactive and idaapi is not None:
            default_virtualenv = base_path / "virtualenv"
            user_input = _prompt_for_path("Provide path to virtualenv", default_virtualenv)
            if user_input and user_input.strip():
                env_path = _normalize_env_path(Path(user_input.strip()), base_path)
                prompt_used = True

    if env_path is None:
        raise ValueError("No active virtualenv")

    if not env_path.is_dir():
        raise ValueError("This path is not a dir: %s" % env_path)

    script_path = env_path / folder / "activate_this.py"
    if not script_path.is_file():
        raise ValueError("Unable to find activate_this.py inside %s" % script_path.parent)

    try:
        exec(script_path.read_text(), {"__file__": str(script_path)})
    except OSError as exc:
        raise ValueError("Unable to read activation script %s: %s" % (script_path, exc)) from exc

    env_path_str = str(env_path)
    if prompt_used:
        suggested_env = env_path
        try:
            suggested_env = env_path.relative_to(base_path)
        except ValueError:
            pass
        message_template = "To avoid prompts on future launches, configure envs.activate_virtualenv_env(virtualenv=%r, base_dir=%r)"
        logger.warning(message_template, str(suggested_env), str(base_path))
        if idaapi is not None:
            idaapi.warning(message_template % (str(suggested_env), str(base_path)))
    return env_path_str


def activate_conda_env(
    base: Optional[str] = None,
    env: Optional[str] = None,
    interactive: bool = True,
) -> str:
    '''Activate a Conda/Mamba environment and return its absolute path.'''

    folder = Path("Scripts" if os.name == "nt" else "bin")
    base_path = _resolve_base_path(base)

    env_path: Optional[Path] = None
    prompt_used = False

    if env:
        env_path = _normalize_env_path(Path(env), base_path)
    else:
        env_var = os.environ.get("CONDA_PREFIX")
        if env_var:
            env_path = Path(env_var).expanduser()
        elif interactive and idaapi is not None:
            default_conda_env = base_path / ".venv_directory"
            user_input = _prompt_for_path("Conda/Mamba - Provide path to env", default_conda_env)
            if user_input and user_input.strip():
                env_path = _normalize_env_path(Path(user_input.strip()), base_path)
                prompt_used = True

    if env_path is None:
        raise ValueError("No active Conda/Mamba env")

    if not (env_path / "conda-meta").is_dir():
        raise ValueError("No conda env detected in %s" % env_path)

    old_os_path = os.environ.get("PATH", "")
    path_parts = [str(env_path), str(env_path / folder)]
    if old_os_path:
        path_parts.append(old_os_path)
    os.environ["PATH"] = os.pathsep.join(path_parts)

    if sys.platform == "win32":
        site_packages = env_path / "Lib" / "site-packages"
    else:
        version_dir = f"python{sys.version_info.major}.{sys.version_info.minor}"
        site_packages = env_path / "lib" / version_dir / "site-packages"
        if not site_packages.is_dir():
            candidates = sorted(env_path.glob("lib/python*/site-packages"))
            if candidates:
                site_packages = candidates[0]

    if not site_packages.is_dir():
        raise ValueError("Unable to locate site-packages inside %s" % env_path)

    prev_sys_path = list(sys.path)
    import site

    site.addsitedir(str(site_packages))
    if not hasattr(sys, "real_prefix"):
        sys.real_prefix = sys.prefix
    sys.prefix = str(env_path)

    new_sys_path = []
    for item in list(sys.path):
        if item not in prev_sys_path:
            new_sys_path.append(item)
            sys.path.remove(item)
    sys.path[:0] = new_sys_path

    env_path_str = str(env_path)
    logger.info("Successfully activated venv for IDAPython: %s", env_path_str)
    if prompt_used:
        suggested_env = env_path
        try:
            suggested_env = env_path.relative_to(base_path)
        except ValueError:
            pass
        message_template = "To avoid prompts on future launches, configure envs.activate_conda_env(env=%r, base=%r)"
        logger.warning(message_template, str(suggested_env), str(base_path))
        if idaapi is not None:
            idaapi.warning(message_template % (str(suggested_env), str(base_path)))
    return env_path_str

def _resolve_base_path(base_dir: Optional[str]) -> Path:
    if base_dir is not None and base_dir.strip():
        return Path(base_dir)
    if idaapi is not None:
        return Path(idaapi.get_user_idadir())
    raise ValueError("base_dir must be provided when running outside of IDA")

# make the env activation functions accessible to the IDA console (7.0+)
sys.modules["__main__"].activate_virtualenv_env = activate_virtualenv_env
sys.modules["__main__"].activate_conda_env = activate_conda_env
