import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.config import settings
from backend.database import engine, Base
from backend.seed import init_db
from backend.api.routes import router
from backend.api.messaging_routes import router as messaging_router

# Initialize Database Schema & Seed Data
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AEGIS-X: Explainable Continuous Breach Exposure & Cyber Risk Intelligence Platform Backend API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=settings.API_V1_STR)
app.include_router(messaging_router, prefix=settings.API_V1_STR)

# Serve Frontend SPA
frontend_path = os.path.abspath("frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/", response_class=FileResponse)
def root():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "ONLINE", "platform": settings.PROJECT_NAME}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=False)
