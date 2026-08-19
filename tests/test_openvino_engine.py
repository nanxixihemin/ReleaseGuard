"""Dependency-free tests for the lazy local OpenVINO engine."""

from __future__ import annotations

from pathlib import Path
import json
from types import ModuleType

import pytest

import releaseguard.ai.openvino_engine as engine_module
from releaseguard.ai.model_config import (
    DEFAULT_MODEL_CONFIG,
    ModelConfig,
    QWEN25_CODER_05B_INT4_REQUIRED_FILES,
)
from releaseguard.ai.openvino_engine import (
    DeviceUnavailableError,
    ModelDownloadError,
    ModelIntegrityError,
    ModelLoadError,
    OpenVINOEngine,
    OptionalDependencyUnavailable,
)


def _write_complete_model(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for filename in DEFAULT_MODEL_CONFIG.required_files:
        (directory / filename).write_bytes(b"fixture")


def _fake_modules(
    monkeypatch: pytest.MonkeyPatch,
    modules: dict[str, ModuleType],
) -> None:
    def fake_import(name: str) -> ModuleType:
        if name in modules:
            return modules[name]
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(engine_module.importlib, "import_module", fake_import)


def _openvino_module(*devices: str) -> ModuleType:
    class FakeCore:
        available_devices = devices

    module = ModuleType("openvino")
    module.Core = FakeCore  # type: ignore[attr-defined]
    return module


def _hub_module(calls: list[dict[str, object]], *, fail_after: int | None = None) -> ModuleType:
    def download(**kwargs: object) -> str:
        calls.append(kwargs)
        if fail_after is not None and len(calls) > fail_after:
            raise RuntimeError("simulated download failure")
        local_dir = Path(str(kwargs["local_dir"]))
        filename = str(kwargs["filename"])
        (local_dir / filename).write_bytes(b"fixture")
        return str(local_dir / filename)

    module = ModuleType("huggingface_hub")
    module.hf_hub_download = download  # type: ignore[attr-defined]
    return module


def test_qwen_model_config_has_a_stable_complete_allowlist() -> None:
    assert DEFAULT_MODEL_CONFIG.model_id == "OpenVINO/Qwen2.5-Coder-0.5B-Instruct-int4-ov"
    assert DEFAULT_MODEL_CONFIG.required_files == QWEN25_CODER_05B_INT4_REQUIRED_FILES
    assert "openvino_model.xml" in DEFAULT_MODEL_CONFIG.required_files
    assert "openvino_model.bin" in DEFAULT_MODEL_CONFIG.required_files
    assert "openvino_tokenizer.xml" in DEFAULT_MODEL_CONFIG.required_files
    assert "openvino_detokenizer.xml" in DEFAULT_MODEL_CONFIG.required_files
    assert "added_tokens.json" in DEFAULT_MODEL_CONFIG.required_files
    assert "merges.txt" in DEFAULT_MODEL_CONFIG.required_files
    assert "vocab.json" in DEFAULT_MODEL_CONFIG.required_files
    assert "openvino_config.json" not in DEFAULT_MODEL_CONFIG.required_files
    assert len(set(DEFAULT_MODEL_CONFIG.required_files)) == len(DEFAULT_MODEL_CONFIG.required_files)


@pytest.mark.parametrize("unsafe_name", ["..", "nested/model", r"nested\\model"])
def test_model_config_rejects_non_simple_model_directory_and_file_names(unsafe_name: str) -> None:
    with pytest.raises(ValueError):
        ModelConfig(
            model_id="owner/model",
            directory_name=unsafe_name,
            required_files=("config.json",),
        )
    with pytest.raises(ValueError):
        ModelConfig(
            model_id="owner/model",
            directory_name="model",
            required_files=(unsafe_name,),
        )


def test_module_and_engine_import_without_optional_ai_dependencies(tmp_path: Path) -> None:
    engine = OpenVINOEngine(model_directory=tmp_path / "model")

    assert engine.is_loaded is False
    assert engine.validate_model_directory() is False


def test_validate_model_directory_requires_every_nonempty_allowlisted_file(tmp_path: Path) -> None:
    model_directory = tmp_path / "model"
    _write_complete_model(model_directory)
    engine = OpenVINOEngine(model_directory=model_directory)

    assert engine.validate_model_directory() is True
    (model_directory / "openvino_model.bin").write_bytes(b"")
    assert engine.validate_model_directory() is False
    assert engine.missing_model_files() == ("openvino_model.bin",)


def test_ensure_model_downloads_only_allowlisted_files_to_partial_then_promotes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    _fake_modules(monkeypatch, {"huggingface_hub": _hub_module(calls)})
    engine = OpenVINOEngine(model_directory=tmp_path / "model")

    model_directory = engine.ensure_model()

    assert model_directory == tmp_path / "model"
    assert engine.validate_model_directory() is True
    assert engine.partial_directory.exists() is False
    assert [call["filename"] for call in calls] == list(DEFAULT_MODEL_CONFIG.required_files)
    assert {Path(str(call["local_dir"])) for call in calls} == {engine.partial_directory}
    engine.ensure_model()
    assert len(calls) == len(DEFAULT_MODEL_CONFIG.required_files)


def test_ensure_model_does_not_promote_an_incomplete_download(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    _fake_modules(monkeypatch, {"huggingface_hub": _hub_module(calls, fail_after=1)})
    engine = OpenVINOEngine(model_directory=tmp_path / "model")

    with pytest.raises(ModelDownloadError):
        engine.ensure_model()

    assert engine.model_directory.exists() is False
    assert engine.partial_directory.exists() is True
    assert engine.validate_model_directory(engine.partial_directory) is False


def test_ensure_model_preserves_partial_downloads_and_only_fetches_missing_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    _fake_modules(monkeypatch, {"huggingface_hub": _hub_module(calls)})
    engine = OpenVINOEngine(model_directory=tmp_path / "model")
    engine.partial_directory.mkdir(parents=True)
    completed_file = DEFAULT_MODEL_CONFIG.required_files[0]
    (engine.partial_directory / completed_file).write_bytes(b"already-downloaded")

    assert engine.ensure_model() == engine.model_directory
    assert (engine.model_directory / completed_file).read_bytes() == b"already-downloaded"
    assert [call["filename"] for call in calls] == list(
        DEFAULT_MODEL_CONFIG.required_files[1:]
    )


def test_ensure_model_promotes_a_completed_previous_partial_without_downloading(
    tmp_path: Path,
) -> None:
    engine = OpenVINOEngine(model_directory=tmp_path / "model")
    _write_complete_model(engine.partial_directory)

    assert engine.ensure_model() == engine.model_directory
    assert engine.validate_model_directory() is True
    assert engine.partial_directory.exists() is False


def test_ensure_model_rejects_a_broken_final_directory_without_overwriting_it(tmp_path: Path) -> None:
    engine = OpenVINOEngine(model_directory=tmp_path / "model")
    engine.model_directory.mkdir()
    (engine.model_directory / "config.json").write_text("broken", encoding="utf-8")

    with pytest.raises(ModelIntegrityError):
        engine.ensure_model()


def test_device_selection_uses_requested_only_when_available_then_gpu_then_cpu(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fake_modules(monkeypatch, {"openvino": _openvino_module("CPU", "GPU.0")})
    engine = OpenVINOEngine(model_directory=tmp_path / "model", requested_device="NPU")

    assert engine.select_device() == "GPU.0"
    assert engine.select_device("CPU") == "CPU"
    assert engine.select_device("gpu") == "GPU.0"


def test_device_selection_honors_available_requested_npu_and_fails_without_cpu_or_gpu(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fake_modules(monkeypatch, {"openvino": _openvino_module("NPU.0", "CPU")})
    engine = OpenVINOEngine(model_directory=tmp_path / "model", requested_device="NPU")
    assert engine.select_device() == "NPU.0"

    _fake_modules(monkeypatch, {"openvino": _openvino_module("NPU")})
    with pytest.raises(DeviceUnavailableError):
        OpenVINOEngine(model_directory=tmp_path / "other").select_device()


def test_device_selection_reports_a_missing_openvino_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fake_modules(monkeypatch, {})

    with pytest.raises(OptionalDependencyUnavailable):
        OpenVINOEngine(model_directory=tmp_path / "model").select_device()


def test_load_reuses_one_pipeline_and_generate_uses_the_selected_device(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_directory = tmp_path / "model"
    _write_complete_model(model_directory)
    pipeline_calls: list[tuple[str, str]] = []

    class FakePipeline:
        def __init__(self, directory: str, device: str) -> None:
            pipeline_calls.append((directory, device))

        def generate(self, prompt: str, **kwargs: object) -> str:
            assert prompt == "Return JSON only"
            assert kwargs == {"max_new_tokens": 64}
            return '{"summary":"ok"}'

    genai = ModuleType("openvino_genai")
    genai.LLMPipeline = FakePipeline  # type: ignore[attr-defined]
    _fake_modules(
        monkeypatch,
        {"openvino": _openvino_module("CPU", "GPU"), "openvino_genai": genai},
    )
    engine = OpenVINOEngine(model_directory=model_directory)

    first = engine.load()
    second = engine.load()

    assert first is second
    assert pipeline_calls == [(str(model_directory), "GPU")]
    assert engine.selected_device == "GPU"
    assert engine.generate("Return JSON only", max_new_tokens=64) == '{"summary":"ok"}'


def test_load_converts_pipeline_initialization_failure_to_a_safe_engine_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_directory = tmp_path / "model"
    _write_complete_model(model_directory)

    class FailingPipeline:
        def __init__(self, *_: object) -> None:
            raise RuntimeError("raw runtime detail")

    genai = ModuleType("openvino_genai")
    genai.LLMPipeline = FailingPipeline  # type: ignore[attr-defined]
    _fake_modules(
        monkeypatch,
        {"openvino": _openvino_module("CPU"), "openvino_genai": genai},
    )

    with pytest.raises(ModelLoadError, match="could not load"):
        OpenVINOEngine(model_directory=model_directory).load()


def test_generate_structured_uses_local_genai_json_schema_constraint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_directory = tmp_path / "model"
    _write_complete_model(model_directory)
    received: dict[str, object] = {}

    class FakeStructuredOutputConfig:
        json_schema: str | None = None

    class FakeGenerationConfig:
        structured_output_config: FakeStructuredOutputConfig | None = None

    class FakePipeline:
        def __init__(self, *_: object) -> None:
            return None

        def generate(self, prompt: str, config: FakeGenerationConfig) -> str:
            received["prompt"] = prompt
            received["config"] = config
            return '{"ok":true}'

    genai = ModuleType("openvino_genai")
    genai.LLMPipeline = FakePipeline  # type: ignore[attr-defined]
    genai.GenerationConfig = FakeGenerationConfig  # type: ignore[attr-defined]
    genai.StructuredOutputConfig = FakeStructuredOutputConfig  # type: ignore[attr-defined]
    _fake_modules(
        monkeypatch,
        {"openvino": _openvino_module("CPU"), "openvino_genai": genai},
    )
    engine = OpenVINOEngine(model_directory=model_directory)

    assert engine.generate_structured(
        "Return JSON",
        {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        max_new_tokens=10,
    ) == '{"ok":true}'
    config = received["config"]
    assert isinstance(config, FakeGenerationConfig)
    assert config.max_new_tokens == 10  # type: ignore[attr-defined]
    assert json.loads(config.structured_output_config.json_schema) == {  # type: ignore[union-attr]
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
    }


def test_generate_falls_back_to_generation_config_when_kwargs_are_not_supported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_directory = tmp_path / "model"
    _write_complete_model(model_directory)

    class FakeGenerationConfig:
        pass

    class ConfigOnlyPipeline:
        def __init__(self, *_: object) -> None:
            pass

        def generate(self, prompt: str, config: FakeGenerationConfig) -> str:
            assert prompt == "Return JSON only"
            assert config.max_new_tokens == 64
            assert config.do_sample is False
            return '{"summary":"ok"}'

    genai = ModuleType("openvino_genai")
    genai.LLMPipeline = ConfigOnlyPipeline  # type: ignore[attr-defined]
    genai.GenerationConfig = FakeGenerationConfig  # type: ignore[attr-defined]
    _fake_modules(
        monkeypatch,
        {"openvino": _openvino_module("CPU"), "openvino_genai": genai},
    )

    engine = OpenVINOEngine(model_directory=model_directory)
    assert engine.generate("Return JSON only", max_new_tokens=64, do_sample=False) == '{"summary":"ok"}'
