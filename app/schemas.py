# app/schemas.py

from pydantic import BaseModel, Field
from typing import Optional, List


class HashRequest(BaseModel):
    message: str = Field(..., description="Сообщение для хеширования")
    key: str = Field(..., description="Секретный ключ для HMAC")
    algorithm: Optional[str] = Field('sha256', description="Алгоритм хеширования (по умолчанию 'sha256')")

class HashResponse(BaseModel):
    signature: str = Field(..., description="Сгенерированный HMAC-хеш")

class AlgorithmsResponse(BaseModel):
    algorithms: List[str] = Field(..., description="Список доступных алгоритмов хеширования")
