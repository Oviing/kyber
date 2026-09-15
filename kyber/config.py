from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    api_keys: str = "dev-key-1"  # comma-separated
    database_url: str = "sqlite:///./kyber.db"
    redis_url: str = "redis://localhost:6379/0"
    sandbox_concurrency: int = 4
    sandbox_timeout_quick: int = 300
    sandbox_timeout_full: int = 900
    sandbox_memory: str = "1g"
    sandbox_cpus: float = 1.0
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str = ""
    artifact_dir: str = "/tmp/kyber-artifacts"

    @property
    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}


settings = Settings()
