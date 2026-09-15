from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    sandbox_image: str = "kyber-sandbox:latest"
    sandbox_memory: str = "1g"
    sandbox_cpus: float = 1.0


settings = Settings()
