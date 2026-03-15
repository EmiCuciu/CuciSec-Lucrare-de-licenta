from fastapi import FastAPI

app = FastAPI(title="CuciSec Api")


@app.get("/")
async def read_root():
    return {"mesaj": "API-ul CuciSec functioneaza"}


@app.get("/items/{item_id}")
async def read_item(item_id: int, q: str | None = None):
    return {"item_id": item_id, "q": q}
