from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict

app = FastAPI(
    title="Secure Auth App",
    description="Hardened API for Sentinel AI testing"
)

# --- MODELS ---

class User(BaseModel):
    user_id: int
    username: str
    is_admin: bool = False


class Document(BaseModel):
    doc_id: int
    owner_id: int
    content: str
    is_public: bool = False


# --- MOCK DATABASES ---

db_users: Dict[int, User] = {
    1: User(user_id=1, username="alice", is_admin=False),
    2: User(user_id=2, username="bob", is_admin=False),
    99: User(user_id=99, username="sysadmin", is_admin=True),
}

db_documents: Dict[int, Document] = {
    101: Document(doc_id=101, owner_id=1, content="Alice's private diary", is_public=False),
    102: Document(doc_id=102, owner_id=2, content="Bob's secret recipe", is_public=False),
    103: Document(doc_id=103, owner_id=99, content="Server master passwords", is_public=False),
}


# --- AUTH DEPENDENCY ---

def get_current_user() -> User:
    """
    Simulated authenticated user.
    In production, extract from JWT.
    """
    return db_users[1]  # Simulate Alice


# --- ENDPOINTS ---

@app.get("/")
def read_root():
    return {"status": "Secure Auth App is running"}


# ✅ FIXED: Proper Object-Level Authorization
@app.get("/api/documents/{doc_id}", response_model=Document)
def get_document(doc_id: int, current_user: User = Depends(get_current_user)):
    document = db_documents.get(doc_id)

    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    # Enforce authorization:
    # Allow if:
    # - Document is public
    # - OR user owns document
    # - OR user is admin
    if not document.is_public and document.owner_id != current_user.user_id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this document"
        )

    return document


# ✅ SAFE UPDATE MODEL (No admin field allowed)
class UserUpdate(BaseModel):
    username: Optional[str] = None


@app.put("/api/users/me", response_model=User)
def update_profile(user_update: UserUpdate, current_user: User = Depends(get_current_user)):
    user = db_users.get(current_user.user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.username is not None:
        user.username = user_update.username

    # 🔒 is_admin cannot be modified via this endpoint

    db_users[user.user_id] = user
    return user


# ✅ Secure Delete (Already Secure, Slightly Improved)
@app.delete("/api/documents/{doc_id}")
def delete_document_secure(doc_id: int, current_user: User = Depends(get_current_user)):
    document = db_documents.get(doc_id)

    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    if document.owner_id != current_user.user_id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this document"
        )

    del db_documents[doc_id]
    return {"status": "success", "deleted_id": doc_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)