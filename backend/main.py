from fastapi import FastAPI, HTTPException, Cookie, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

app = FastAPI()

# フロントエンドからの通信を許可する設定（CORS）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080","http://localhost:5500", "http://127.0.0.1:5500"], # フロントエンドのURLに合わせて変更
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# サーバーの基本設定
RP_ID = "localhost"
RP_NAME = "Demo App"
EXPECTED_ORIGIN = "http://localhost:8080" # フロントエンドのURL

# 簡易データベース（実運用ではMySQL等を使用）
mock_db = {
    "user_id": b"student_12345", # ユーザーのシステム内部ID
    "credentials": [],           # 保存された公開鍵のリスト
    "current_challenge": ""      # 発行中のチャレンジを一時保存
}

# ==========================================
# 【フェーズ1】登録 (Registration)
# ==========================================

@app.get("/api/register/options")
def get_register_options():
    """1. フロントエンドに登録用のオプション（チャレンジ等）を渡す"""
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=mock_db["user_id"],
        user_name="student@example.com",
    )
    mock_db["current_challenge"] = options.challenge
    return options_to_json(options)

@app.post("/api/register/verify")
def verify_register(credential_data: dict):
    """2. フロントエンドから送られてきた公開鍵を検証・保存する"""
    try:
        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=mock_db["current_challenge"],
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
        )
        
        # 検証に成功したら、Credential IDと公開鍵をDBに保存
        mock_db["credentials"].append({
            "id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count,
        })
        return {"status": "success", "message": "登録完了！公開鍵を保存しました。"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ==========================================
# 【フェーズ2】ログイン (Authentication)
# ==========================================

@app.get("/api/login/options")
def get_login_options():
    """3. フロントエンドにログイン用のオプション（挑戦状）を渡す"""
    # 登録済みのCredential IDリストを取得
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=cred["id"]) for cred in mock_db["credentials"]
    ]
    
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
    )
    mock_db["current_challenge"] = options.challenge
    return options_to_json(options)

@app.post("/api/login/verify")
def verify_login(credential_data: dict, response: Response):
    """4. 送られてきた署名を検証し、成功すればCookieを発行する"""
    if not mock_db["credentials"]:
        raise HTTPException(status_code=400, detail="ユーザーが登録されていません")

    # DBから該当の公開鍵データを探す
    stored_cred = next(
        (c for c in mock_db["credentials"] if c["id"] == base64url_to_bytes(credential_data.get("id"))),
        None
    )
    if not stored_cred:
        raise HTTPException(status_code=400, detail="不明なCredential IDです")

    try:
        # 署名の検証
        verification = verify_authentication_response(
            credential=credential_data, # ブラウザから送られてきた「署名（ハンコ）」
            expected_challenge=mock_db["current_challenge"], # サーバーが出した乱数
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=stored_cred["public_key"], # 台帳に登録されている「公開鍵（印鑑証明）」
            credential_current_sign_count=stored_cred["sign_count"],
        )
        
        # 次回以降の検証のために、署名カウンターを更新（クローン攻撃対策）
        stored_cred["sign_count"] = verification.new_sign_count
        
        # 【追加】検証に成功したら、Cookie（通行証）を発行する
        response.set_cookie(
            key="session_token",
            value="valid_user_pass", # 今回は簡略化のため固定文字列
            httponly=True,           # JavaScriptからのアクセスを禁止（XSS対策）
            samesite="lax"           # CSRF対策
        )
        
        return {"status": "success", "message": "ログイン成功！通行証を発行しました。"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==========================================
# 【フェーズ3】Nginxからのアクセス審査 (Authorization)
# ==========================================

@app.get("/api/verify_session")
def verify_session(session_token: str | None = Cookie(default=None)):
    """
    5. Nginxが「この通信を通していいか？」を問い合わせてくる専用窓口
    """
    # Cookieの中に正しい通行証（今回は "valid_user_pass"）があるかチェック
    if session_token == "valid_user_pass":
        # 問題なければ 200 OK を返す（Nginxが通信を許可する）
        return Response(status_code=status.HTTP_200_OK)
    
    # 通行証がない、または不正な場合は 401 Unauthorized を返す（Nginxが通信を遮断する）
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="認証されていません。通行証がありません。"
    )