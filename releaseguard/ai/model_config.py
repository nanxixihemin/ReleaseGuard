"""Static, dependency-free model definitions for the local OpenVINO analyzer.

The model files are deliberately allowlisted.  The engine never asks a model
hub for a repository snapshot, which keeps a model refresh from silently
introducing additional artifacts into the local Skill cache.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath, PureWindowsPath


def _is_simple_name(value: object) -> bool:
    """Return whether ``value`` is one portable, non-special path component."""

    if not isinstance(value, str) or not value or value in {".", ".."}:
        return False
    return all(
        path.name == value and len(path.parts) == 1
        for path in (PurePath(value), PurePosixPath(value), PureWindowsPath(value))
    )


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """An immutable OpenVINO model package definition.

    ``required_files`` is both the download allowlist and the completeness
    contract used before a partially downloaded model can be promoted.
    """

    model_id: str
    directory_name: str
    required_files: tuple[str, ...]
    fallback_model_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.model_id, str) or self.model_id.count("/") != 1:
            raise ValueError("model_id must identify a model-hub repository")
        organization, repository = self.model_id.split("/", maxsplit=1)
        if not organization or not repository:
            raise ValueError("model_id must identify a model-hub repository")
        if not _is_simple_name(self.directory_name):
            raise ValueError("directory_name must be a single directory name")
        if not self.required_files:
            raise ValueError("required_files must not be empty")
        if len(set(self.required_files)) != len(self.required_files):
            raise ValueError("required_files must not contain duplicates")
        for filename in self.required_files:
            if not _is_simple_name(filename):
                raise ValueError("required model files must be simple filenames")
        if self.fallback_model_id is not None:
            if (
                not isinstance(self.fallback_model_id, str)
                or self.fallback_model_id.count("/") != 1
                or not all(self.fallback_model_id.split("/", maxsplit=1))
            ):
                raise ValueError("fallback_model_id must identify a model-hub repository")


# The OpenVINO GenAI pipeline needs the compressed IR, OpenVINO tokenizer and
# detokenizer IRs, plus the configuration/tokenizer assets supplied with this
# model package.  Keep this tuple in model-hub order for deterministic tests
# and deterministic download behavior.
QWEN25_CODER_05B_INT4_REQUIRED_FILES: tuple[str, ...] = (
    "added_tokens.json",
    "config.json",
    "generation_config.json",
    "merges.txt",
    "openvino_model.bin",
    "openvino_model.xml",
    "openvino_tokenizer.bin",
    "openvino_tokenizer.xml",
    "openvino_detokenizer.bin",
    "openvino_detokenizer.xml",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
)

QWEN25_CODER_05B_INT4_CONFIG = ModelConfig(
    model_id="OpenVINO/Qwen2.5-Coder-0.5B-Instruct-int4-ov",
    directory_name="Qwen2.5-Coder-0.5B-Instruct-int4-ov",
    required_files=QWEN25_CODER_05B_INT4_REQUIRED_FILES,
    fallback_model_id="OpenVINO/Phi-3.5-mini-instruct-int4-ov",
)

DEFAULT_MODEL_CONFIG = QWEN25_CODER_05B_INT4_CONFIG


__all__ = [
    "DEFAULT_MODEL_CONFIG",
    "ModelConfig",
    "QWEN25_CODER_05B_INT4_CONFIG",
    "QWEN25_CODER_05B_INT4_REQUIRED_FILES",
]
