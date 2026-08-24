from fastapi import FastAPI
from app.database import engine, Base
from app.routes import custom_ocsf, normalizer

# Create database tables automatically on startup if they don't exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Cybreach Custom OCSF Schema Engine",
    version="2.0.0",
    description="API for managing custom OCSF schema definitions with Redis caching and log normalization"
)

# Include both API Routers
app.include_router(custom_ocsf.router)
app.include_router(normalizer.router)


@app.get("/", tags=["Health Check"])
def root():
    return {
        "status": "online",
        "service": "Cybreach Engine",
        "version": "2.0.0"
    }