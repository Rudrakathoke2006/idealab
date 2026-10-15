import os

class Settings:
    PROJECT_NAME: str = "AEGIS-X: Explainable Continuous Breach Exposure & Risk Intelligence Platform"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "aegis_x_super_secret_jwt_key_2026_secure_hash")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aegis_x.db")

    # AEGIS-X Secure Incident Messaging (Matrix / E2EE) Settings
    AEGIS_MESSAGING_ENABLED: bool = os.getenv("AEGIS_MESSAGING_ENABLED", "true").lower() in ("true", "1", "yes")
    AEGIS_PUBLIC_URL: str = os.getenv("AEGIS_PUBLIC_URL", "http://localhost:8000")
    MATRIX_HOMESERVER_URL: str = os.getenv("MATRIX_HOMESERVER_URL", "https://chat.aegis-x.internal")
    MATRIX_SERVER_NAME: str = os.getenv("MATRIX_SERVER_NAME", "chat.aegis-x.internal")
    MESSAGING_ALLOW_CROSS_TENANT: bool = os.getenv("MESSAGING_ALLOW_CROSS_TENANT", "false").lower() in ("true", "1", "yes")
    MESSAGING_REQUIRE_DEVICE_VERIFICATION: bool = os.getenv("MESSAGING_REQUIRE_DEVICE_VERIFICATION", "true").lower() in ("true", "1", "yes")
    MESSAGING_POLICY_VERSION: str = "messaging-policy-v1"

settings = Settings()
