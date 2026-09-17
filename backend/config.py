import os

class Settings:
    PROJECT_NAME: str = "AEGIS-X: Explainable Continuous Breach Exposure & Risk Intelligence Platform"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "aegis_x_super_secret_jwt_key_2026_secure_hash")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aegis_x.db")

settings = Settings()
