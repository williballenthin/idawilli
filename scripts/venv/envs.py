# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

import os
import sys
from pathlib import Path
from typing import Optional

import idaapi


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
    print("Detecting Python virtual environment...")

    # Normalize input: treat empty strings as None
    if env is not None and not str(env).strip():
        env = None

    # Fast path: already inside an environment
    already_active = os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX")
    if already_active:
        print(" - Environment already active: %s" % already_active)
        return True

    # Helper to try an activation once, then retry exactly once with defaults
    def _try_env(label, func, args_primary, kwargs_primary, args_fallback, kwargs_fallback) -> bool:
        try:
            path = func(*args_primary, **kwargs_primary)
            print(" - %s activated: %s" % (label, path))
            return True
        except ValueError as e:
            print(" - %s: %s (retrying with defaults)" % (label, e))
            try:
                path = func(*args_fallback, **kwargs_fallback)
                print(" - %s activated on retry: %s" % (label, path))
                return True
            except ValueError as e2:
                print(" - %s retry failed: %s" % (label, e2))
                return False
        except Exception as e:
            # Defensive guard: unexpected errors shouldn't bring down detection
            print(" - %s unexpected error: %s" % (label, e))
            return False

    # 1) virtualenv: primary with provided env, fallback with defaults (no args)
    if _try_env(
        "Virtualenv",
        activate_virtualenv_env,
        (env,), {"interactive": False},
        tuple(), {},
    ):
        return True

    # 2) conda: primary with provided env, fallback with defaults (no args)
    if _try_env(
        "Conda",
        activate_conda_env,
        (None, env), {"interactive": False},
        tuple(), {},
    ):
        return True

    print(" - No Python environment activated.")
    return False


def _prompt_for_path(prompt: str, default: Path) -> Optional[str]:
    '''Ask the user for a filesystem path through the IDA UI.'''

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

    base_path = Path(base_dir or idaapi.get_user_idadir())
    folder = Path("Scripts" if os.name == "nt" else "bin")

    env_path: Optional[Path] = None

    if virtualenv:
        env_path = _normalize_env_path(Path(virtualenv), base_path)
    else:
        env_var = os.environ.get("VIRTUAL_ENV")
        if env_var:
            env_path = Path(env_var).expanduser()
        elif interactive:
            default_virtualenv = base_path / "virtualenv"
            user_input = _prompt_for_path("Provide path to virtualenv", default_virtualenv)
            if user_input and user_input.strip():
                env_path = _normalize_env_path(Path(user_input.strip()), base_path)

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

    return str(env_path)


def activate_conda_env(
    base: Optional[str] = None,
    env: Optional[str] = None,
    interactive: bool = True,
) -> str:
    '''Activate a Conda/Mamba environment and return its absolute path.'''

    folder = Path("Scripts" if os.name == "nt" else "bin")
    base_path = Path(base or idaapi.get_user_idadir())

    env_path: Optional[Path] = None

    if env:
        env_path = _normalize_env_path(Path(env), base_path)
    else:
        env_var = os.environ.get("CONDA_PREFIX")
        if env_var:
            env_path = Path(env_var).expanduser()
        elif interactive:
            user_input = _prompt_for_path("Conda/Mamba - Provide path to env", base_path)
            if user_input and user_input.strip():
                env_path = _normalize_env_path(Path(user_input.strip()), base_path)

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

    print("Successfully activated venv for IDAPython: %s" % env_path)
    return str(env_path)


# make the env activation functions accessible to the IDA console (7.0+)
sys.modules["__main__"].activate_virtualenv_env = activate_virtualenv_env
sys.modules["__main__"].activate_conda_env = activate_conda_env
