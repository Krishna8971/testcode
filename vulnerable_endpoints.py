from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict

app = FastAPI(title="Vulnerable Auth App", description="Intentionally vulnerable API for Sentinel AI testing")

# --- MOCK INFRASTRUCTURE ---

class User(BaseModel):
    user_id: int
    username: str
    is_admin: bool = False

class Document(BaseModel):
    doc_id: int
    owner_id: int
    content: str
    is_public: bool = False

# Mock Databases
db_users: Dict[int, User] = {
    1: User(user_id=1, username="alice", is_admin=False),
    2: User(user_id=2, username="bob", is_admin=False),
    99: User(user_id=99, username="sysadmin", is_admin=True)
}

db_documents: Dict[int, Document] = {
    101: Document(doc_id=101, owner_id=1, content="Alice's private diary", is_public=False),
    102: Document(doc_id=102, owner_id=2, content="Bob's secret recipe", is_public=False),
    103: Document(doc_id=103, owner_id=99, content="Server master passwords", is_public=False)
}

# Mock Authentication Dependency
def get_current_user() -> User:
    """
    In a real app, this would extract a JWT token from headers.
    For this test app, we hardcode returning 'Alice' (user_id=1).
    """
    return db_users[1]


# --- API ENDPOINTS ---

@app.get("/")
def read_root():
    return {"status": "Vulnerable Auth App is running"}

# VULNERABILITY 1: Broken Object Level Authorization (BOLA) / IDOR
# Any authenticated user can read ANY document simply by guessing the doc_id.
# The server checks if the document exists, but fails to check if the
# current_user.user_id == document.owner_id.
@app.get("/api/documents/{doc_id}", response_model=Document)
def get_document(doc_id: int, current_user: User = Depends(get_current_user)):
    document = db_documents.get(doc_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
        
    # VULNERABILITY: Missing authorization check!
    # A proper implementation would do: 
    # if not document.is_public and document.owner_id != current_user.user_id:
    #     raise HTTPException(...)
        
    return document


# VULNERABILITY 2: Privilege Escalation (Mass Assignment)
# The endpoint allows updating a profile, but the `user_update` payload
# inherently includes the `is_admin` boolean field from the base model.
# A malicious user can submit `{"username": "hacker", "is_admin": true}`
# to illegally elevate their privileges.
class UserUpdate(BaseModel):
    username: Optional[str] = None
    is_admin: Optional[bool] = None # Dangerous mass-assignment vector

@app.put("/api/users/me", response_model=User)
def update_profile(user_update: UserUpdate, current_user: User = Depends(get_current_user)):
    user = db_users.get(current_user.user_id)
    
    if user_update.username is not None:
        user.username = user_update.username
        
    # VULNERABILITY: Blindly applying sensitive payload fields!
    if user_update.is_admin is not None:
        user.is_admin = user_update.is_admin
        
    # Save back to db
    db_users[user.user_id] = user
    return user


# (SECURE ENDPOINT FOR COMPARISON)
@app.delete("/api/documents/{doc_id}")
def delete_document_secure(doc_id: int, current_user: User = Depends(get_current_user)):
    document = db_documents.get(doc_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
        
    # SECURE: Explicitly verifying ownership before destructive action
    if document.owner_id != current_user.user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete this document")
        
    del db_documents[doc_id]
    return {"status": "success", "deleted_id": doc_id}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
