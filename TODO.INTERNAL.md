# Internal TODO

- [ ] Make `maxTokens` dynamic based on the selected model — currently hardcoded to `16384` in `agentic/api.py:483`. Different models have different max output token limits; switching model can cause errors.
- [ ] Test the AI agent with models other than Claude Opus 4.6 (e.g. GPT, OpenRouter models, Bedrock) — verify chain execution, tool calling, and phase transitions work correctly across providers.
