from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    APP_NAME: str = "RiskPath AI - Context-Aware Cybersecurity Decision Support"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    DATABASE_URL: str = Field(default="sqlite:///./cybersecurity.db")
    API_V1_STR: str = "/api"
    SECRET_KEY: str = Field(default="riskpath-secret-key-change-in-production")
    MAX_GRAPH_NODES: int = 10000
    MAX_GRAPH_EDGES: int = 50000
    
    # Seeding & environment configuration
    SEED_DEMO_DATA: bool = Field(default=True)
    CORS_ORIGINS: str = Field(
        default="http://localhost:5173,http://localhost:8080,http://127.0.0.1:5173,http://127.0.0.1:8080"
    )

    # AI configuration
    AI_PROVIDER: str = Field(default="groq")
    AI_MODEL: str = Field(default="llama-3.3-70b-versatile")
    GROQ_API_KEY: str = Field(default="")
    OPENAI_API_KEY: str = Field(default="")
    GEMINI_API_KEY: str = Field(default="")
    AI_TIMEOUT_SECONDS: float = Field(default=30.0)
    AI_MAX_RETRIES: int = Field(default=1)
    AI_BASE_URL: str = Field(default="")

    @property
    def cors_origins_list(self) -> List[str]:
        if not self.CORS_ORIGINS:
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()