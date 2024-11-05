# app/main.py
from fastapi import FastAPI, HTTPException
from starlette.responses import JSONResponse

from app.schemas import HashRequest, HashResponse, AlgorithmsResponse
import hmac
import hashlib
from hashlib import algorithms_available

app = FastAPI(
    title="HMAC SHA256 API",
    description="API для генерации HMAC-хеша с использованием различных алгоритмов хеширования.",
    version="1.0.0"
)

from fastapi import Request

@app.get("/", include_in_schema=False)
async def root(request: Request):
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse(content={
        "message": "Добро пожаловать в HMAC Hashing API.",
        "available_endpoints": {
            "Generate Hash": f"{base_url}/hash"
        },
        "documentation": {
            "Swagger UI": f"{base_url}/docs",
            "ReDoc": f"{base_url}/redoc",
            "OpenAPI Spec": f"{base_url}/openapi.json"
        }
    })

@app.get("/algorithms", response_model=AlgorithmsResponse, summary="Получить доступные алгоритмы")
async def get_algorithms():
    """
    ### Получение доступных алгоритмов
    **Пример ответа

    ```json
    {
      "algorithms": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
    }
    :return:
    """
    algorithms = sorted(hashlib.algorithms_guaranteed)
    return AlgorithmsResponse(algorithms=algorithms)


@app.post("/hash", response_model=HashResponse, summary="Генерация HMAC-хеша")
async def generate_hash(request: HashRequest):
    """
    **Генерирует HMAC-хеш** для заданного сообщения и ключа с использованием указанного алгоритма хеширования.

    **Параметры**:

    - **message**: сообщение для хеширования.
    - **key**: секретный ключ для HMAC.
    - **algorithm**: алгоритм хеширования (по умолчанию 'sha256').

    **Пример запроса**:

    ```json
    {
      "message": "Hello, World!",
      "key": "secret",
      "algorithm": "sha256"
    }
    ```

    **Пример ответа**:

    ```json
    {
      "signature": "aef123..."
    }
    ```
    """
    algorithm = request.algorithm.lower()
    if algorithm not in algorithms_available:
        raise HTTPException(status_code=400, detail=f"Алгоритм '{algorithm}' не поддерживается.")

    try:
        hash_func = getattr(hashlib, algorithm)
    except AttributeError:
        raise HTTPException(status_code=400, detail=f"Алгоритм '{algorithm}' не найден в hashlib.")

    signature = hmac.new(
        key=request.key.encode(),
        msg=request.message.encode(),
        digestmod=hash_func
    ).hexdigest()

    return HashResponse(signature=signature)
