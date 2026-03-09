from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
README_PATH = PROJECT_ROOT / "README.md"


def test_readme_example_assets_exist() -> None:
    readme = README_PATH.read_text()
    expected_assets = (
        "docs/readme/overview.svg",
        "docs/readme/disasm-import.svg",
        "docs/readme/error-symbol.svg",
    )

    for asset in expected_assets:
        assert asset in readme
        assert (PROJECT_ROOT / asset).is_file()
