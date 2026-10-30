"""Optional LLM provider integration for agentic analysis enhancement."""

import os
from typing import Optional


class LLMProvider:
    """Manages optional LLM enhancement via Gemini API or compatible providers."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.model = model
        self._client = None
        if self.api_key:
            self._init_client()

    def _init_client(self):
        try:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
        except Exception:
            self._client = None

    @property
    def is_available(self) -> bool:
        return self._client is not None

    def synthesize_insights(self, prompt: str) -> Optional[str]:
        """Calls the LLM to generate an SRE incident analysis narrative."""
        if not self.is_available:
            return None

        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            return f"(LLM analysis could not be completed: {str(e)})"
