from typing import Optional

from pydantic import BaseModel, validator


class CreateUser(BaseModel):
    username: str
    password: str
    email: str

    @validator("password")
    def secure_password(cls, value):
        if len(value) <= 6:
            return ValueError("Password is too short")
        return value


class UpdateUser(BaseModel):
    username: Optional[str]
    password: Optional[str]
    email: Optional[str]

    @validator("password")
    def secure_password(cls, value):
        if len(value) <= 6:
            return ValueError("Password is too short")
        return value
