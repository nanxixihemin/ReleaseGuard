"""Lazy, local OpenVINO GenAI model lifecycle management.

This module intentionally has no import-time dependency on OpenVINO,
OpenVINO GenAI, or Hugging Face Hub.  Phase 1 callers can therefore import the
ReleaseGuard package without a model runtime installed.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from threading import Lock
from types import ModuleType
from typing import Any

from .model_config import DEFAULT_MODEL_CONFIG, ModelConfig


class OpenVINOEngineError(RuntimeError):
    """Base class for safe, advisory-facing local model engine failures."""


class OptionalDependencyUnavailable(OpenVINOEngineError):
    """Raised when an optional local AI dependency is not installed."""


class ModelIntegrityError(OpenVINOEngineError):
    """Raised when a model directory does not satisfy its allowlist contract."""


class ModelDownloadError(OpenVINOEngineError):
    """Raised when a local model download or promotion cannot complete."""


class DeviceUnavailableError(OpenVINOEngineError):
    """Raised when OpenVINO reports neither an eligible GPU nor CPU device."""


class ModelLoadError(OpenVINOEngineError):
    """Raised when a validated model cannot be loaded into one local pipeline."""


class ModelGenerationError(OpenVINOEngineError):
    """Raised when the loaded local pipeline cannot generate a response."""


def default_model_cache_dir() -> Path:
    """Return a per-user cache location without creating it during import."""

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "ReleaseGuard" / "models"
    return Path.home() / "AppData" / "Local" / "ReleaseGuard" / "models"


def _optional_module(module_name: str, package_hint: str) -> ModuleType:
    """Load an optional dependency only when the local AI path is invoked."""

    try:
        module = importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError) as error:
        raise OptionalDependencyUnavailable(
            f"{package_hint} is required for the local OpenVINO analyzer."
        ) from error
    if not isinstance(module, ModuleType):
        raise OptionalDependencyUnavailable(f"{package_hint} could not be imported.")
    return module


class OpenVINOEngine:
    """Download, validate, load, and reuse one local OpenVINO GenAI pipeline.

    Engine errors contain only operational summaries.  The future pipe server
    can safely convert them into advisory ``AIReview`` failures without leaking
    model prompts, findings, or raw local source content.
    """

    def __init__(
        self,
        *,
        config: ModelConfig = DEFAULT_MODEL_CONFIG,
        models_directory: str | Path | None = None,
        model_directory: str | Path | None = None,
        requested_device: str | None = None,
    ) -> None:
        if models_directory is not None and model_directory is not None:
            raise ValueError("pass either models_directory or model_directory, not both")

        self.config = config
        if model_directory is not None:
            self.model_directory = Path(model_directory).expanduser()
        else:
            cache_directory = (
                Path(models_directory).expanduser()
                if models_directory is not None
                else default_model_cache_dir()
            )
            self.model_directory = cache_directory / config.directory_name
        self.partial_directory = self.model_directory.with_name(
            f"{self.model_directory.name}.partial"
        )
        self.requested_device = requested_device
        self._pipeline: Any | None = None
        self._genai: Any | None = None
        self._selected_device: str | None = None
        self._load_lock = Lock()

    @property
    def selected_device(self) -> str | None:
        """The verified device used by the resident pipeline, if loaded."""

        return self._selected_device

    @property
    def is_loaded(self) -> bool:
        """Whether this engine currently holds one initialized pipeline."""

        return self._pipeline is not None

    def missing_model_files(self, directory: str | Path | None = None) -> tuple[str, ...]:
        """Return required files that are absent or empty in ``directory``."""

        candidate_directory = Path(directory) if directory is not None else self.model_directory
        if not candidate_directory.is_dir():
            return self.config.required_files

        missing: list[str] = []
        for filename in self.config.required_files:
            candidate = candidate_directory / filename
            try:
                if not candidate.is_file() or candidate.stat().st_size <= 0:
                    missing.append(filename)
            except OSError:
                missing.append(filename)
        return tuple(missing)

    def validate_model_directory(self, directory: str | Path | None = None) -> bool:
        """Return whether ``directory`` contains every allowlisted required file."""

        return not self.missing_model_files(directory)

    def ensure_model(self) -> Path:
        """Return a complete local model directory, downloading it if necessary.

        Downloads land in ``<model>.partial``.  Only a directory that passes the
        full file allowlist check is atomically renamed into the final location.
        A broken final directory is never overwritten automatically.
        """

        if self.validate_model_directory():
            return self.model_directory
        if self.model_directory.exists():
            missing = ", ".join(self.missing_model_files())
            raise ModelIntegrityError(
                f"The local model directory is incomplete; missing: {missing}."
            )

        if self.validate_model_directory(self.partial_directory):
            return self._promote_partial_directory()

        self._prepare_partial_directory()
        downloader = self._huggingface_downloader()
        try:
            for filename in self.missing_model_files(self.partial_directory):
                downloader(
                    repo_id=self.config.model_id,
                    filename=filename,
                    local_dir=str(self.partial_directory),
                )
        except Exception as error:
            raise ModelDownloadError("The local OpenVINO model download did not complete.") from error

        missing = self.missing_model_files(self.partial_directory)
        if missing:
            raise ModelDownloadError(
                "The local OpenVINO model download is incomplete; required files are missing."
            )
        return self._promote_partial_directory()

    def select_device(self, requested_device: str | None = None) -> str:
        """Choose a verified requested device, otherwise GPU first and CPU second."""

        openvino = _optional_module("openvino", "OpenVINO")
        core_type = getattr(openvino, "Core", None)
        if not callable(core_type):
            raise OptionalDependencyUnavailable("OpenVINO Core is unavailable in the local runtime.")
        try:
            available_devices = tuple(str(device) for device in core_type().available_devices)
        except Exception as error:
            raise DeviceUnavailableError("OpenVINO could not enumerate local devices.") from error

        target = requested_device if requested_device is not None else self.requested_device
        if target:
            selected = self._available_device(available_devices, target)
            if selected is not None:
                return selected

        for preferred in ("GPU", "CPU"):
            selected = self._available_device(available_devices, preferred)
            if selected is not None:
                return selected
        raise DeviceUnavailableError("No supported local OpenVINO GPU or CPU device is available.")

    def load(self) -> Any:
        """Initialize and retain exactly one ``openvino_genai.LLMPipeline``."""

        with self._load_lock:
            if self._pipeline is not None:
                return self._pipeline

            model_directory = self.ensure_model()
            device = self.select_device()
            genai = _optional_module("openvino_genai", "OpenVINO GenAI")
            pipeline_type = getattr(genai, "LLMPipeline", None)
            if not callable(pipeline_type):
                raise OptionalDependencyUnavailable(
                    "OpenVINO GenAI LLMPipeline is unavailable in the local runtime."
                )
            try:
                pipeline = pipeline_type(str(model_directory), device)
            except Exception as error:
                raise ModelLoadError(
                    f"The local OpenVINO model could not load on device {device}."
                ) from error
            self._pipeline = pipeline
            self._genai = genai
            self._selected_device = device
            return pipeline

    def generate(self, prompt: str, **generation_kwargs: Any) -> str:
        """Generate one response through the resident pipeline without logging it."""

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        pipeline = self.load()
        try:
            response = pipeline.generate(prompt, **generation_kwargs)
        except TypeError as direct_kwargs_error:
            if not generation_kwargs:
                raise ModelGenerationError(
                    "The local OpenVINO model could not generate a response."
                ) from direct_kwargs_error
            try:
                generation_config = self._generation_config(generation_kwargs)
                response = pipeline.generate(prompt, generation_config)
            except OpenVINOEngineError:
                raise
            except Exception as error:
                raise ModelGenerationError(
                    "The local OpenVINO model could not generate a response."
                ) from error
        except Exception as error:
            raise ModelGenerationError("The local OpenVINO model could not generate a response.") from error

        return self._response_text(response)

    def generate_structured(
        self,
        prompt: str,
        json_schema: dict[str, Any],
        **generation_kwargs: Any,
    ) -> str:
        """Generate JSON constrained by a local OpenVINO GenAI schema."""

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        if not isinstance(json_schema, dict):
            raise ValueError("json_schema must be an object")
        pipeline = self.load()
        genai = self._genai or _optional_module("openvino_genai", "OpenVINO GenAI")
        structured_type = getattr(genai, "StructuredOutputConfig", None)
        if not callable(structured_type):
            raise ModelGenerationError(
                "The installed OpenVINO GenAI runtime does not support structured output."
            )
        try:
            config = self._generation_config(generation_kwargs)
            structured_output = structured_type()
            structured_output.json_schema = json.dumps(json_schema, ensure_ascii=False)
            config.structured_output_config = structured_output
            response = pipeline.generate(prompt, config)
        except OpenVINOEngineError:
            raise
        except Exception as error:
            raise ModelGenerationError(
                "The local OpenVINO model could not generate structured output."
            ) from error
        return self._response_text(response)

    @staticmethod
    def _response_text(response: Any) -> str:
        """Normalize supported GenAI response objects without logging content."""

        if isinstance(response, str):
            return response
        response_text = getattr(response, "text", None)
        if isinstance(response_text, str):
            return response_text
        response_texts = getattr(response, "texts", None)
        if isinstance(response_texts, (list, tuple)) and response_texts and isinstance(response_texts[0], str):
            return response_texts[0]
        raise ModelGenerationError("The local OpenVINO model returned an unsupported response type.")

    def _prepare_partial_directory(self) -> None:
        """Create or retain the controlled staging directory for resumable downloads."""

        if self.partial_directory.exists():
            if not self.partial_directory.is_dir():
                raise ModelDownloadError("The local model staging path is not a directory.")
            return
        try:
            self.partial_directory.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            raise ModelDownloadError("The local model staging directory could not be created.") from error

    def _promote_partial_directory(self) -> Path:
        """Atomically promote a validated staging directory to its final path."""

        if not self.validate_model_directory(self.partial_directory):
            raise ModelIntegrityError("The local model staging directory is incomplete.")
        if self.model_directory.exists():
            raise ModelIntegrityError("The final local model directory already exists and was not replaced.")
        try:
            self.partial_directory.replace(self.model_directory)
        except OSError as error:
            raise ModelDownloadError("The validated local model could not be promoted into place.") from error
        return self.model_directory

    def _huggingface_downloader(self) -> Any:
        hub = _optional_module("huggingface_hub", "Hugging Face Hub")
        downloader = getattr(hub, "hf_hub_download", None)
        if not callable(downloader):
            raise OptionalDependencyUnavailable(
                "Hugging Face Hub download support is unavailable in the local runtime."
            )
        return downloader

    def _generation_config(self, generation_kwargs: dict[str, Any]) -> Any:
        """Adapt keyword settings for GenAI builds that require GenerationConfig."""

        genai = self._genai
        if genai is None:
            genai = _optional_module("openvino_genai", "OpenVINO GenAI")
        config_type = getattr(genai, "GenerationConfig", None)
        if not callable(config_type):
            raise ModelGenerationError(
                "The installed OpenVINO GenAI runtime does not support generation settings."
            )
        try:
            generation_config = config_type()
            for name, value in generation_kwargs.items():
                setattr(generation_config, name, value)
            return generation_config
        except Exception as error:
            raise ModelGenerationError(
                "The local OpenVINO generation settings could not be configured."
            ) from error

    @staticmethod
    def _available_device(available_devices: tuple[str, ...], requested: str) -> str | None:
        normalized_requested = requested.strip().upper()
        if not normalized_requested:
            return None
        for device in available_devices:
            if device.upper() == normalized_requested:
                return device
        requested_base = normalized_requested.split(".", maxsplit=1)[0]
        if normalized_requested == requested_base:
            for device in available_devices:
                if device.upper().split(".", maxsplit=1)[0] == requested_base:
                    return device
        return None


__all__ = [
    "DeviceUnavailableError",
    "ModelDownloadError",
    "ModelGenerationError",
    "ModelIntegrityError",
    "ModelLoadError",
    "OpenVINOEngine",
    "OpenVINOEngineError",
    "OptionalDependencyUnavailable",
    "default_model_cache_dir",
]
