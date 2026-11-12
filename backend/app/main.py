from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .api import router
from .db import engine
from .security import current_user

app = FastAPI(title="HackingBara", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": exc.detail}
    return JSONResponse({"error": {**detail, "code": exc.status_code}}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Never reflect submitted inputs, which may contain passwords.
    errors = [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]
    return JSONResponse(
        {"error": {"code": 422, "message": "Validation failed", "details": errors}}, status_code=422
    )


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        }
    )
    return response


@app.get("/health")
def health():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/api/v1/openapi.json", dependencies=[Depends(current_user)])
def schema():
    return app.openapi()


@app.get("/api/v1/docs", dependencies=[Depends(current_user)])
def docs():
    return get_swagger_ui_html(openapi_url="/api/v1/openapi.json", title="HackingBara API")
