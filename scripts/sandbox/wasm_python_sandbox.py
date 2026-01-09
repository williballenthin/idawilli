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
3. Passing complex data (dict with list) via stdin/stdout JSON protocol
4. Defining host functions using Func, FuncType, ValType, and Linker
5. Bidirectional communication with exposed host functions
6. Fuel-based execution limiting

Technical Background on Host Functions:
---------------------------------------
WebAssembly modules can import functions from the host environment. In wasmtime-py,
you define these using:
- FuncType: Defines the function signature (parameter and return types)
- ValType: Represents WASM value types (i32, i64, f32, f64, externref, funcref)
- Func: Wraps a Python callable as a WASM-callable function
- Linker: Registers imports and instantiates modules

IMPORTANT LIMITATION: The pre-built VMware Labs CPython WASM only imports standard
WASI functions. For a guest Python script to call custom host functions, you would
need to either:
1. Build a custom CPython WASM with additional imports (using __import_module__ in C)
2. Use the WASI Component Model (more complex, emerging standard)

This demo shows BOTH:
- How to properly define host functions (for educational purposes and custom builds)
- Practical workarounds using stdin/stdout JSON protocol for the pre-built CPython

Usage:
    uv run wasm_python_sandbox.py

The python-3.12.0.wasm file must be present in the same directory as this script,
along with the usr/ directory containing the Python standard library.
"""

from __future__ import annotations

import json
import logging
import sys
import tempfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Callable

from wasmtime import (
    Config,
    Engine,
    Func,
    FuncType,
    Linker,
    Module,
    Store,
    ValType,
    WasiConfig,
)

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


def create_engine(*, use_fuel: bool = False) -> Engine:
    """Create a wasmtime Engine with optional fuel limiting."""
    config = Config()
    if use_fuel:
        config.consume_fuel = True
    config.cache = True
    return Engine(config)


def run_python_code(
    code: str,
    *,
    stdin_data: str | None = None,
    use_fuel: bool = False,
    fuel_limit: int = 400_000_000,
) -> ExecutionResult:
    """
    Execute Python code in a WASM sandbox.

    Args:
        code: Python source code to execute
        stdin_data: Optional string to provide as stdin to the sandbox
        use_fuel: Whether to limit execution by fuel consumption
        fuel_limit: Maximum fuel units if use_fuel is True

    Returns:
        ExecutionResult with stdout, stderr, and execution metadata
    """
    if not PYTHON_WASM.exists():
        raise FileNotFoundError(f"Python WASM not found: {PYTHON_WASM}")
    if not PYTHON_LIB.exists():
        raise FileNotFoundError(f"Python lib not found: {PYTHON_LIB}")

    engine = create_engine(use_fuel=use_fuel)

    linker = Linker(engine)
    linker.define_wasi()

    logger.info("Loading Python WASM module...")
    python_module = Module.from_file(engine, str(PYTHON_WASM))

    with tempfile.TemporaryDirectory() as workdir:
        workdir_path = Path(workdir)

        stdout_file = workdir_path / "stdout.log"
        stderr_file = workdir_path / "stderr.log"
        stdin_file = workdir_path / "stdin.txt"
        stdout_file.touch()
        stderr_file.touch()

        if stdin_data is not None:
            stdin_file.write_text(stdin_data)
        else:
            stdin_file.touch()

        script_file = workdir_path / "script.py"
        script_file.write_text(code)

        wasi_config = WasiConfig()
        wasi_config.argv = ("python", "/sandbox/script.py")
        wasi_config.stdout_file = str(stdout_file)
        wasi_config.stderr_file = str(stderr_file)
        wasi_config.stdin_file = str(stdin_file)

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
    print("\n" + "=" * 70)
    print("Demo 1: Basic Execution with stdout/stderr capture")
    print("=" * 70)

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


def demo_stdin_stdout_communication():
    """
    Demonstrate passing complex data via stdin/stdout JSON protocol.

    This is the cleanest way to communicate with the pre-built CPython WASM:
    - Host writes JSON to stdin
    - Guest reads from stdin, processes, writes JSON to stdout
    - Host reads and parses the result
    """
    print("\n" + "=" * 70)
    print("Demo 2: Complex Data via stdin/stdout JSON Protocol")
    print("=" * 70)

    input_data = {
        "name": "test_experiment",
        "parameters": {"learning_rate": 0.001, "batch_size": 32},
        "data_points": [1.5, 2.7, 3.14, 4.2, 5.0],
        "tags": ["ml", "training", "v1"],
    }

    code = '''
import sys
import json

# Read input from stdin
input_json = sys.stdin.read()
data = json.loads(input_json)

print("Received complex data structure:", file=sys.stderr)
print(f"  Name: {data['name']}", file=sys.stderr)
print(f"  Parameters: {data['parameters']}", file=sys.stderr)
print(f"  Data points: {data['data_points']}", file=sys.stderr)
print(f"  Tags: {data['tags']}", file=sys.stderr)

# Process the data
total = sum(data["data_points"])
avg = total / len(data["data_points"])

# Return result as JSON on stdout (clean protocol)
result = {
    "input_name": data["name"],
    "sum": total,
    "average": avg,
    "point_count": len(data["data_points"]),
}
print(json.dumps(result))
'''

    print(f"Sending to sandbox via stdin: {json.dumps(input_data, indent=2)}")
    result = run_python_code(code, stdin_data=json.dumps(input_data))

    print(f"\nSandbox stderr (status messages):\n{result.stderr}")
    print(f"Sandbox stdout (result):\n{result.stdout}")

    if result.stdout.strip():
        parsed_result = json.loads(result.stdout.strip())
        print(f"Parsed result from sandbox: {parsed_result}")


def demo_host_function_definitions():
    """
    Demonstrate how to define host functions using Func, FuncType, ValType, Linker.

    This shows the proper wasmtime-py API for defining host functions that WASM
    modules can import. While the pre-built CPython WASM won't call these
    (it only imports WASI functions), this demonstrates the pattern for:
    - Custom WASM builds
    - Educational purposes
    - Other WASM modules you might use
    """
    print("\n" + "=" * 70)
    print("Demo 3: Host Function Definitions (Func, FuncType, ValType, Linker)")
    print("=" * 70)

    print("\nThis demo shows HOW to define host functions in wasmtime-py.")
    print("Note: Pre-built CPython WASM only imports WASI functions, so it")
    print("cannot call these directly. For that, you'd need a custom build.\n")

    engine = Engine()
    store = Store(engine)
    linker = Linker(engine)
    linker.define_wasi()

    # Track calls for demonstration
    call_log: list[str] = []

    # Example 1: Simple function with no parameters, no return
    def host_log_message():
        call_log.append("host_log_message called")
        print("  [HOST] Log message from host function!")

    log_func_type = FuncType([], [])  # () -> ()
    log_func = Func(store, log_func_type, host_log_message)
    linker.define(store, "env", "log_message", log_func)
    print("Defined: env.log_message() -> void")
    print(f"  FuncType: {log_func_type}")

    # Example 2: Function with i32 parameters and i32 return
    def host_add_numbers(a: int, b: int) -> int:
        call_log.append(f"host_add_numbers({a}, {b})")
        result = a + b
        print(f"  [HOST] Adding {a} + {b} = {result}")
        return result

    add_func_type = FuncType([ValType.i32(), ValType.i32()], [ValType.i32()])
    add_func = Func(store, add_func_type, host_add_numbers)
    linker.define(store, "env", "add_numbers", add_func)
    print("\nDefined: env.add_numbers(i32, i32) -> i32")
    print(f"  FuncType: {add_func_type}")

    # Example 3: Function with i64 and f64 types
    def host_compute(x: int, y: float) -> float:
        call_log.append(f"host_compute({x}, {y})")
        result = float(x) * y
        print(f"  [HOST] Computing {x} * {y} = {result}")
        return result

    compute_func_type = FuncType([ValType.i64(), ValType.f64()], [ValType.f64()])
    compute_func = Func(store, compute_func_type, host_compute)
    linker.define(store, "math", "compute", compute_func)
    print("\nDefined: math.compute(i64, f64) -> f64")
    print(f"  FuncType: {compute_func_type}")

    # Example 4: Function with access_caller=True for memory access
    def host_process_buffer(caller, ptr: int, length: int) -> int:
        """
        Host function that can access the caller's memory.
        The 'caller' parameter (when access_caller=True) provides access to
        the calling module's exports, including its memory.
        """
        call_log.append(f"host_process_buffer(ptr={ptr}, len={length})")
        print(f"  [HOST] Processing buffer at ptr={ptr}, length={length}")

        # Access the module's exported memory
        memory = caller.get("memory")
        if memory is not None:
            # Read bytes from the guest's memory
            # data = memory.data_ptr(caller)[ptr:ptr+length]
            print(f"  [HOST] Would read {length} bytes from memory at offset {ptr}")
        else:
            print("  [HOST] No memory export found")

        return length  # Return bytes processed

    buffer_func_type = FuncType([ValType.i32(), ValType.i32()], [ValType.i32()])
    buffer_func = Func(store, buffer_func_type, host_process_buffer, access_caller=True)
    linker.define(store, "env", "process_buffer", buffer_func)
    print("\nDefined: env.process_buffer(i32 ptr, i32 len) -> i32")
    print(f"  FuncType: {buffer_func_type}")
    print("  Note: Uses access_caller=True for memory access via Caller object")

    # Show available ValTypes
    print("\n" + "-" * 50)
    print("Available ValType constructors:")
    print("  ValType.i32()     - 32-bit integer")
    print("  ValType.i64()     - 64-bit integer")
    print("  ValType.f32()     - 32-bit float")
    print("  ValType.f64()     - 64-bit float")
    print("  ValType.externref() - External reference")
    print("  ValType.funcref()   - Function reference")

    print("\n" + "-" * 50)
    print("Host functions registered on linker:")
    print("  env.log_message")
    print("  env.add_numbers")
    print("  math.compute")
    print("  env.process_buffer")
    print("\nThese would be available to any WASM module that imports them.")


def demo_host_function_with_complex_data():
    """
    Demonstrate a practical host function pattern with complex data.

    Since WASM only supports primitive types (i32, i64, f32, f64), passing
    complex data like dicts requires serialization. This demo shows the pattern:

    1. Guest serializes data to JSON
    2. Guest writes JSON to a buffer and passes pointer/length to host
    3. Host reads from guest memory, deserializes, processes
    4. Host serializes result, writes to guest memory
    5. Host returns pointer/length of result
    6. Guest reads and deserializes result

    For the pre-built CPython WASM, we simulate this via stdin/stdout.
    """
    print("\n" + "=" * 70)
    print("Demo 4: Host Function with Complex Data (dict with list)")
    print("=" * 70)

    def host_transform_data(data: dict[str, Any]) -> dict[str, Any]:
        """
        Host-side function that transforms complex data.
        Takes a dict with a list, returns a dict with transformed data.
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

    # Simulate calling the host function via stdin/stdout protocol
    request_data = {
        "function": "transform_data",
        "args": {"items": [10, 20, 30, 40, 50], "multiplier": 3},
    }

    sandbox_code = '''
import sys
import json

# Read the function call request from stdin
request = json.loads(sys.stdin.read())
print(f"Sandbox received request: {request}", file=sys.stderr)

# Extract function name and args
func_name = request["function"]
args = request["args"]

# Simulate "calling" the host function by outputting the request
# In a real scenario with custom WASM imports, this would be a direct call
result_request = {
    "type": "host_function_call",
    "function": func_name,
    "args": args,
}
print(json.dumps(result_request))
'''

    print("Step 1: Sandbox prepares host function call request...")
    result = run_python_code(sandbox_code, stdin_data=json.dumps(request_data))
    print(f"Sandbox stderr:\n{result.stderr}")

    if result.stdout.strip():
        call_request = json.loads(result.stdout.strip())
        print(f"\nStep 2: Host receives call request: {call_request}")

        # Process with the host function
        response = host_transform_data(call_request["args"])
        print(f"\nStep 3: Host function transforms data:")
        print(f"  Input: {call_request['args']}")
        print(f"  Output: {response}")

        # Send response back to sandbox
        response_code = f'''
import sys
import json

# Read host function response from stdin
response = json.loads(sys.stdin.read())
print(f"Sandbox received host response: {{response}}", file=sys.stderr)

# Process the response further in the sandbox
final_result = {{
    "status": "success",
    "host_response_sum": response["sum"],
    "doubled_items": [x * 2 for x in response["transformed_items"]],
}}
print(json.dumps(final_result))
'''

        print("\nStep 4: Sandbox processes host response...")
        final_result = run_python_code(
            response_code, stdin_data=json.dumps(response)
        )
        print(f"Sandbox stderr:\n{final_result.stderr}")

        if final_result.stdout.strip():
            parsed_final = json.loads(final_result.stdout.strip())
            print(f"\nFinal result from sandbox: {parsed_final}")


def demo_fuel_limiting():
    """Demonstrate fuel-based execution limiting for resource control."""
    print("\n" + "=" * 70)
    print("Demo 5: Fuel-Based Execution Limiting")
    print("=" * 70)

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
    demo_stdin_stdout_communication()
    demo_host_function_definitions()
    demo_host_function_with_complex_data()
    demo_fuel_limiting()

    print("\n" + "=" * 70)
    print("All demos completed!")
    print("=" * 70)
    print("\nSummary:")
    print("- Demo 1-2: Shows practical communication with pre-built CPython WASM")
    print("- Demo 3: Shows how to define host functions (Func, FuncType, ValType)")
    print("- Demo 4: Shows complex data passing pattern (dict with list)")
    print("- Demo 5: Shows resource limiting via fuel consumption")
    print("\nFor true synchronous host function calls from Python in WASM,")
    print("you would need to build a custom CPython WASM with additional imports.")


if __name__ == "__main__":
    main()
