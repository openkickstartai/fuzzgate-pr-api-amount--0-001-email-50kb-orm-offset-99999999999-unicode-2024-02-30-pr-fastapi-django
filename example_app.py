"""Example vulnerable FastAPI app for FuzzGate demo."""
from fastapi import FastAPI

app = FastAPI(title="Demo Vulnerable API")


@app.get("/users/{user_id}")
def get_user(user_id: int):
    """Vulnerable: raises unhandled ValueError for negative IDs."""
    if user_id < 0:
        raise ValueError(f"Invalid user ID: {user_id}")
    return {"id": user_id, "name": "Alice"}


@app.get("/search")
def search(q: str = "", offset: int = 0):
    """Vulnerable: crashes on large offset values."""
    if offset > 1_000_000:
        raise RuntimeError("Simulated DB timeout from large offset")
    return {"q": q, "offset": offset, "results": []}


@app.get("/health")
def health():
    """Safe endpoint with no parameters."""
    return {"status": "ok"}
