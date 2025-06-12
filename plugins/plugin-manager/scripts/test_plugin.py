import sys
import subprocess
import tempfile
import shutil
import os
from pathlib import Path

PROJ_ROOT = Path(__file__).parent.parent
IDALIB_PATH = Path("/Applications/IDA Professional 9.1.app/Contents/MacOS/idalib/python/")


def run_command(cmd, show_output=True):
    """Helper to run shell commands."""
    cmd_str = ' '.join(map(str, cmd))
    if show_output:
        print(f"RUNNING COMMAND: {cmd_str}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if show_output:
        print(f"STATUS: {result.returncode}")
        if result.stdout:
            print(f"STDOUT ---------------------------------- \n{result.stdout}")
        if result.stderr:
            print(f"STDERR ---------------------------------- \n{result.stderr}")
        print("------------------------------------------")

    if result.returncode != 0:
        raise RuntimeError(f"subprocess failed: status code: {result.returncode}")

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_plugin.py <path_to_plugin_wheel>")
        print("Example: python test_plugin.py dist/basic_ida_plugin-0.1.0-py3-none-any.whl")
        sys.exit(1)
    whl_path = Path(sys.argv[1]).resolve()

    if not whl_path.exists():
        print(f"Error: Plugin wheel not found at {whl_path}")
        sys.exit(1)

    if not IDALIB_PATH.is_dir():
        print(f"Error: IDA Python library directory not found at {IDALIB_PATH}")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        venv_path = Path(tmpdir)

        # 1. Initialize virtualenv with uv
        run_command(["uv", "venv", "--no-project", "--seed", str(venv_path)], show_output=False)
        pip_executable = venv_path / "bin" / "pip"
        python_executable = venv_path / "bin" / "python"

        # 2. Install idalib into the venv (needed for ippm and potentially plugin manager itself)
        run_command([str(pip_executable), "install", str(IDALIB_PATH)], show_output=False)

        # 3. Change directory to PROJ_ROOT
        os.chdir(PROJ_ROOT)

        # 4. Remove build and dist directories
        for d in ["build", "dist"]:
            dir_to_remove = PROJ_ROOT / d
            if dir_to_remove.exists():
                shutil.rmtree(dir_to_remove)

        run_command(["uv", "build", "--wheel"], show_output=False)

        # 5. Install idapro_plugin_manager wheel
        plugin_manager_wheels = list(PROJ_ROOT.glob("dist/idapro_plugin_manager-*.whl"))
        if not plugin_manager_wheels:
            print("Error: idapro_plugin_manager wheel not found in dist/. Please build it first (e.g., by running 'python -m build').")
            sys.exit(1)
        assert len(plugin_manager_wheels) == 1
        plugin_manager_wheel = plugin_manager_wheels[0]
        run_command([str(pip_executable), "install", str(plugin_manager_wheel)], show_output=False)

        # 6. Register the plugin manager
        ippm_executable = venv_path / "bin" / "ippm"
        run_command([str(ippm_executable), "register"], show_output=True)

        # 7. Install the target plugin wheel
        run_command([str(pip_executable), "install", str(whl_path)], show_output=True)

        # 8. Run trivial_idalib.py via IDA and capture output
        test_dll_source_path = PROJ_ROOT / "tests" / "data" / "Practical Malware Analysis Lab 01-01.dll_"
        test_dll_path = venv_path / "test.dll"
        shutil.copy2(test_dll_source_path, test_dll_path)

        trivial_idalib_script = PROJ_ROOT / "scripts" / "trivial_idalib.py"

        result = run_command([
            str(python_executable),
            str(trivial_idalib_script),
            str(test_dll_path),
        ], show_output=True)

        if "Library not loaded" in result.stderr and "PyQt5/QtWidgets" in result.stderr:
            print("WARNING: plugin requires Qt GUI library that we can't test here in a headless environment")
            # we can't reall tell if the plugin is going to work
            # but at least some of its code loads.

        else:
            assert "error" not in result.stdout.lower()
            assert "failed to load" not in result.stderr.lower()

    sys.exit(0)

if __name__ == "__main__":
    main()
