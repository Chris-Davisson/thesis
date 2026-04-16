"""Inference backend abstractions for LLM providers."""

from abc import ABC, abstractmethod
from typing import Literal

OLLAMA_DEFAULT_HOST = "http://127.0.0.1:11434"
VLLM_DEFAULT_HOST = "http://localhost:8000"


class InferenceBackend(ABC):
    """Abstract base class for LLM inference backends."""

    model: str
    host: str

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate a response from a single prompt string."""

    @abstractmethod
    def chat(self, messages: list[dict]) -> str:
        """Generate a response from a list of chat messages.

        Each message dict has 'role' and 'content' keys.
        """

    @abstractmethod
    def validate_model(self) -> None:
        """Validate the model is available on this backend.

        Raises ValueError if unavailable.
        """


class OllamaBackend(InferenceBackend):
    """Ollama backend for local LLM inference."""

    def __init__(self, model: str, host: str = OLLAMA_DEFAULT_HOST):
        try:
            from ollama import Client
        except ImportError:
            raise ImportError(
                "ollama package not installed. Run: pip install ollama"
            )

        self.model = model
        self.host = host
        self.client = Client(host=host)
        self.validate_model()

    def validate_model(self) -> None:
        try:
            models = self.client.list()
            model_names = [
                m.get("name", m.get("model", ""))
                for m in models.get("models", [])
            ]
            if not any(self.model in name for name in model_names):
                raise ValueError(f"Model '{self.model}' not found in Ollama")
        except Exception as e:
            if "not found" in str(e).lower():
                raise
            raise ValueError(
                f"Cannot connect to Ollama at {self.host}. "
                f"Ensure Ollama is running (ollama serve).\nError: {e}"
            )

    def generate(self, prompt: str) -> str:
        response = self.client.generate(model=self.model, prompt=prompt)
        return response["response"].strip()

    def chat(self, messages: list[dict]) -> str:
        response = self.client.chat(model=self.model, messages=messages)
        return response["message"]["content"].strip()


class VLLMBackend(InferenceBackend):
    """vLLM backend using OpenAI-compatible API."""

    def __init__(self, model: str, host: str = VLLM_DEFAULT_HOST, api_key: str = "EMPTY"):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )

        self.model = model
        self.host = host
        self.client = OpenAI(
            base_url=f"{host.rstrip('/')}/v1",
            api_key=api_key,
        )
        self.validate_model()

    def validate_model(self) -> None:
        try:
            models = self.client.models.list()
            model_ids = [m.id for m in models.data]
            if self.model not in model_ids:
                available = ", ".join(model_ids) if model_ids else "none"
                raise ValueError(
                    f"Model '{self.model}' not found on vLLM server. "
                    f"Available models: {available}"
                )
        except Exception as e:
            if "not found" in str(e).lower():
                raise
            raise ValueError(
                f"Cannot connect to vLLM at {self.host}. "
                f"Ensure vLLM server is running.\nError: {e}"
            )

    def generate(self, prompt: str) -> str:
        response = self.client.completions.create(
            model=self.model,
            prompt=prompt,
            max_tokens=1024,
            temperature=0.1,
        )
        return response.choices[0].text.strip()

    def chat(self, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=2048,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


class APIBackend(InferenceBackend):
    """Remote OpenAI-compatible API backend (DeepSeek, OpenAI, etc.).

    Unlike VLLMBackend, this skips model validation since remote APIs
    may not support the models.list() endpoint.
    """

    def __init__(self, model: str, host: str, api_key: str = "EMPTY"):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )

        self.model = model
        self.host = host
        self.client = OpenAI(
            base_url=f"{host.rstrip('/')}/v1" if not host.rstrip('/').endswith('/v1') else host.rstrip('/'),
            api_key=api_key,
        )

    def validate_model(self) -> None:
        # Remote APIs don't reliably support model listing — skip validation
        pass

    def generate(self, prompt: str) -> str:
        response = self.client.completions.create(
            model=self.model,
            prompt=prompt,
            max_tokens=1024,
            temperature=0.1,
        )
        return response.choices[0].text.strip()

    def chat(self, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=2048,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()


BackendType = Literal["ollama", "vllm", "api"]


def create_backend(
    backend: BackendType,
    model: str,
    host: str | None = None,
    api_key: str = "EMPTY",
) -> InferenceBackend:
    """Factory function to create the appropriate backend."""
    if backend == "ollama":
        return OllamaBackend(model, host or OLLAMA_DEFAULT_HOST)
    elif backend == "vllm":
        return VLLMBackend(model, host or VLLM_DEFAULT_HOST, api_key=api_key)
    elif backend == "api":
        if not host:
            raise ValueError("API backend requires a host URL (e.g. https://api.deepseek.com)")
        return APIBackend(model, host, api_key=api_key)
    else:
        raise ValueError(f"Unknown backend: {backend}")
