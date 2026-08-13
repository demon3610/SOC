from fastapi import APIRouter, WebSocket, WebSocketException, Query, status
from jose import JWTError, jwt
from app.config import SECRET_KEY, ALGORITHM
from app.ws_manager import connect, disconnect

router = APIRouter()


@router.websocket("/ws/projects/{project_id}/live")
async def websocket_live(project_id: int, websocket: WebSocket, token: str = Query(...)):
    """Live event stream for a project; auth via ?token= (user JWT)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    except JWTError:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    await connect(project_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        disconnect(project_id, websocket)
