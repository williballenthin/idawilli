#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "wasmtime>=23.0.0",
# ]
# ///
"""
Demonstrates running Python code inside a WebAssembly sandbox using wasmtime-py
and VMware Labs' CPython WASM build.

Features demonstrated:
1. Loading and running CPython WASM interpreter
2. Capturing stdout/stderr from the sandbox
3. Passing complex data (dict with list) into the sandbox via files
4. Getting complex results back via stdout
5. Host function simulation via file-based IPC

Usage:
    uv run wasm_python_sandbox.py

The python-3.12.0.wasm file must be present in the same directory as this script,
along with the usr/ directory containing the Python standard library.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wasmtime import Config, Engine, Linker, Module, Store, WasiConfig

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).parent.resolve()
PYTHON_WASM = SCRIPT_DIR / "python-3.12.0.wasm"
PYTHON_LIB = SCRIPT_DIR / "usr" / "local" / "lib"


@dataclass
class ExecutionResult:
    """Result of executing Python code in the WASM sandbox."""

    stdout: str
    stderr: str
    fuel_consumed: int | None = None
    success: bool = True


def create_engine(*, use_fuel: bool = False, fuel_limit: int = 400_000_000) -> Engine:
    """Create a wasmtime Engine with optional fuel limiting."""
    config = Config()
    if use_fuel:
        config.consume_fuel = True
    config.cache = True
    return Engine(config)


def run_python_code(
    code: str,
    *,
    input_data: dict[str, Any] | None = None,
    use_fuel: bool = False,
    fuel_limit: int = 400_000_000,
) -> ExecutionResult:
    """
    Execute Python code in a WASM sandbox.

    Args:
        code: Python source code to execute
        input_data: Optional dict to pass to the sandbox (available as /input.json)
        use_fuel: Whether to limit execution by fuel consumption
        fuel_limit: Maximum fuel units if use_fuel is True

    Returns:
        ExecutionResult with stdout, stderr, and execution metadata
    """
    if not PYTHON_WASM.exists():
        raise FileNotFoundError(f"Python WASM not found: {PYTHON_WASM}")
    if not PYTHON_LIB.exists():
        raise FileNotFoundError(f"Python lib not found: {PYTHON_LIB}")

    engine = create_engine(use_fuel=use_fuel, fuel_limit=fuel_limit)

    linker = Linker(engine)
    linker.define_wasi()

    logger.info("Loading Python WASM module...")
    python_module = Module.from_file(engine, str(PYTHON_WASM))

    with tempfile.TemporaryDirectory() as workdir:
        workdir_path = Path(workdir)

        stdout_file = workdir_path / "stdout.log"
        stderr_file = workdir_path / "stderr.log"
        stdout_file.touch()
        stderr_file.touch()

        script_file = workdir_path / "script.py"
        script_file.write_text(code)

        if input_data is not None:
            input_file = workdir_path / "input.json"
            input_file.write_text(json.dumps(input_data))

        wasi_config = WasiConfig()
        wasi_config.argv = ("python", "/sandbox/script.py")
        wasi_config.stdout_file = str(stdout_file)
        wasi_config.stderr_file = str(stderr_file)

        wasi_config.preopen_dir(str(workdir_path), "/sandbox")
        wasi_config.preopen_dir(str(PYTHON_LIB), "/usr/local/lib")

        store = Store(engine)
        if use_fuel:
            store.set_fuel(fuel_limit)
        store.set_wasi(wasi_config)

        instance = linker.instantiate(store, python_module)
        start_fn = instance.exports(store)["_start"]

        logger.info("Executing Python code in sandbox...")
        success = True
        try:
            start_fn(store)
        except Exception as e:
            logger.warning(f"Execution ended with: {e}")
            success = False

        stdout = stdout_file.read_text()
        stderr = stderr_file.read_text()

        fuel_consumed = None
        if use_fuel:
            remaining = store.get_fuel()
            fuel_consumed = fuel_limit - remaining

        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            fuel_consumed=fuel_consumed,
            success=success,
        )


def demo_basic_execution():
    """Demonstrate basic code execution with stdout/stderr capture."""
    print("\n" + "=" * 60)
    print("Demo 1: Basic Execution with stdout/stderr capture")
    print("=" * 60)

    code = '''
import sys

print("Hello from the WASM sandbox!")
print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")

print("This goes to stderr", file=sys.stderr)
'''

    result = run_python_code(code)
    print(f"\nstdout:\n{result.stdout}")
    print(f"stderr:\n{result.stderr}")


def demo_complex_data_passing():
    """Demonstrate passing complex data structures into the sandbox."""
    print("\n" + "=" * 60)
    print("Demo 2: Passing Complex Data (dict with list) into Sandbox")
    print("=" * 60)

    input_data = {
        "name": "test_experiment",
        "parameters": {
            "learning_rate": 0.001,
            "batch_size": 32,
        },
        "data_points": [1.5, 2.7, 3.14, 4.2, 5.0],
        "tags": ["ml", "training", "v1"],
    }

    code = '''
import json

with open("/sandbox/input.json") as f:
    data = json.load(f)

print("Received complex data structure:")
print(f"  Name: {data['name']}")
print(f"  Parameters: {data['parameters']}")
print(f"  Data points: {data['data_points']}")
print(f"  Tags: {data['tags']}")

# Process the data
total = sum(data["data_points"])
avg = total / len(data["data_points"])

# Return result as JSON on stdout
result = {
    "input_name": data["name"],
    "sum": total,
    "average": avg,
    "point_count": len(data["data_points"]),
}
print("---RESULT_JSON---")
print(json.dumps(result))
'''

    result = run_python_code(code, input_data=input_data)
    print(f"\nstdout:\n{result.stdout}")

    if "---RESULT_JSON---" in result.stdout:
        json_str = result.stdout.split("---RESULT_JSON---")[1].strip()
        parsed_result = json.loads(json_str)
        print(f"\nParsed result from sandbox: {parsed_result}")


def demo_host_function_simulation():
    """
    Demonstrate simulating a host function call from the sandbox.

    This shows a pattern where the sandbox can "call" host functions by:
    1. Writing a request to a file
    2. The host reads and processes the request
    3. The host writes the response back
    4. The sandbox reads the response

    Since WASM execution is synchronous, we simulate this with a multi-step approach:
    - Guest writes all requests to a file
    - Guest executes with limited capability
    - Host processes requests post-execution (or uses a more complex IPC setup)

    For a true synchronous host function call, you would need to either:
    - Build a custom CPython with WASM imports for your functions
    - Use a more sophisticated IPC mechanism with threads/async

    This demo shows the practical file-based pattern commonly used for sandboxed execution.
    """
    print("\n" + "=" * 60)
    print("Demo 3: Host Function Simulation via File-Based IPC")
    print("=" * 60)

    def host_transform_data(data: dict[str, Any]) -> dict[str, Any]:
        """
        Host-side function that transforms data.
        This demonstrates a function that takes a complex object (dict with list)
        and returns a complex result.
        """
        items = data.get("items", [])
        multiplier = data.get("multiplier", 1)

        transformed = {
            "original_count": len(items),
            "transformed_items": [x * multiplier for x in items],
            "sum": sum(x * multiplier for x in items),
            "metadata": {
                "processed_by": "host_transform_data",
                "multiplier_used": multiplier,
            },
        }
        return transformed

    input_for_sandbox = {
        "host_function_input": {
            "items": [10, 20, 30, 40, 50],
            "multiplier": 3,
        }
    }

    sandbox_code = '''
import json

with open("/sandbox/input.json") as f:
    data = json.load(f)

# Prepare a "request" to the host function
request = data["host_function_input"]
print(f"Sandbox: Preparing request for host function: {request}")

# In a real scenario, the sandbox would write this request and somehow
# signal the host. For this demo, we output it in a structured way.
print("---HOST_FUNCTION_REQUEST---")
print(json.dumps(request))
print("---END_REQUEST---")

# Note: In a synchronous host function scenario, you would need additional
# mechanisms to actually pause execution and resume after the host responds.
# This demo shows the data passing pattern.
'''

    print("\nStep 1: Running sandbox code that prepares a host function request...")
    result = run_python_code(sandbox_code, input_data=input_for_sandbox)
    print(f"Sandbox stdout:\n{result.stdout}")

    if "---HOST_FUNCTION_REQUEST---" in result.stdout:
        request_part = result.stdout.split("---HOST_FUNCTION_REQUEST---")[1]
        request_json = request_part.split("---END_REQUEST---")[0].strip()
        request_data = json.loads(request_json)

        print(f"\nStep 2: Host received request: {request_data}")
        response = host_transform_data(request_data)
        print(f"Step 3: Host function returned: {response}")

        response_code = f'''
import json

# In a real IPC scenario, this response would come from a file written by the host
response = {json.dumps(response)}

print("Sandbox received host function response:")
print(f"  Original count: {{response['original_count']}}")
print(f"  Transformed items: {{response['transformed_items']}}")
print(f"  Sum: {{response['sum']}}")
print(f"  Metadata: {{response['metadata']}}")

# Process the response further
final_result = {{
    "status": "success",
    "host_response_sum": response["sum"],
    "doubled_items": [x * 2 for x in response["transformed_items"]],
}}
print("---FINAL_RESULT---")
print(json.dumps(final_result))
'''

        print("\nStep 4: Running sandbox code with host response...")
        final_result = run_python_code(response_code)
        print(f"Final sandbox stdout:\n{final_result.stdout}")


def demo_fuel_limiting():
    """Demonstrate fuel-based execution limiting for resource control."""
    print("\n" + "=" * 60)
    print("Demo 4: Fuel-Based Execution Limiting")
    print("=" * 60)

    code = '''
# Simple computation that uses some fuel
total = 0
for i in range(1000):
    total += i
print(f"Sum of 0..999 = {total}")
'''

    result = run_python_code(code, use_fuel=True, fuel_limit=500_000_000)
    print(f"\nstdout:\n{result.stdout}")
    print(f"Fuel consumed: {result.fuel_consumed:,} units")
    print(f"Execution successful: {result.success}")

    print("\nNow trying with very limited fuel (will likely fail)...")
    limited_result = run_python_code(code, use_fuel=True, fuel_limit=1_000_000)
    print(f"Execution successful: {limited_result.success}")
    if not limited_result.success:
        print("Execution was terminated due to fuel exhaustion (as expected)")


def main():
    print("WASM Python Sandbox Demo")
    print("Using wasmtime-py with VMware Labs CPython WASM build")
    print(f"WASM binary: {PYTHON_WASM}")
    print(f"Python lib: {PYTHON_LIB}")

    if not PYTHON_WASM.exists():
        print(f"\nError: {PYTHON_WASM} not found!", file=sys.stderr)
        print("Please ensure the WASM files are present.", file=sys.stderr)
        sys.exit(1)

    demo_basic_execution()
    demo_complex_data_passing()
    demo_host_function_simulation()
    demo_fuel_limiting()

    print("\n" + "=" * 60)
    print("All demos completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
