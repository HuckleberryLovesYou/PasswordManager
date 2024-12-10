
class Config:
    database_filepath: str = ""
    is_database_found: bool = False
    is_database_encrypted: bool = True
    salt_filepath: str = ""
    salt: bytes = b""
    key: bytes = b""
