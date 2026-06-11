const API_BASE = "/api";

function showMessage(msg, isError = false) {
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = 'block';
    resultDiv.style.backgroundColor = isError ? '#ffebee' : '#e8f5e9';
    resultDiv.style.color = isError ? '#c62828' : '#2e7d32';
    resultDiv.innerHTML = `<strong>${isError ? 'エラー' : '成功'}</strong><br>${msg}`;
}

function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    bytes.forEach(b => str += String.fromCharCode(b));
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLToBuffer(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/\-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    const buffer = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        buffer[i] = rawData.charCodeAt(i);
    }
    return buffer.buffer;
}

// ==========================================
// フェーズ1: 登録 (Registration)
// ==========================================
async function registerUser() {
    try {
        const optRes = await fetch(`${API_BASE}/register/options`);
        const optionsStr = await optRes.json();
        const options = JSON.parse(optionsStr);

        options.challenge = base64URLToBuffer(options.challenge);
        options.user.id = base64URLToBuffer(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const attestationResponse = {
            id: credential.id,
            rawId: bufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64URL(credential.response.attestationObject),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
            },
        };

        const verifyRes = await fetch(`${API_BASE}/register/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attestationResponse)
        });
        
        const result = await verifyRes.json();
        if (verifyRes.ok) showMessage(result.message);
        else showMessage(result.detail, true);

    } catch (error) {
        console.error(error);
        showMessage("登録中にエラーが発生しました。コンソールを確認してください。", true);
    }
}

// ==========================================
// フェーズ2: ログイン (Authentication)
// ==========================================
async function loginUser() {
    try {
        const optRes = await fetch(`${API_BASE}/login/options`);
        if (!optRes.ok) throw new Error("サーバーからオプションを取得できませんでした");
        const optionsStr = await optRes.json();
        const options = JSON.parse(optionsStr);

        // ログイン時は user.id は存在しないので challenge のみ変換
        options.challenge = base64URLToBuffer(options.challenge);
        
        if (options.allowCredentials) {
            options.allowCredentials.forEach(cred => {
                cred.id = base64URLToBuffer(cred.id);
            });
        }

        const assertion = await navigator.credentials.get({ publicKey: options });

        if (!assertion) {
            throw new Error("認証がキャンセルされました");
        }

        const assertionResponse = {
            id: assertion.id,
            rawId: bufferToBase64URL(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
                signature: bufferToBase64URL(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64URL(assertion.response.userHandle) : null,
            },
        };

        const verifyRes = await fetch(`${API_BASE}/login/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(assertionResponse)
        });

        const result = await verifyRes.json();
        if (verifyRes.ok) {
            showMessage(result.message);
            // ログイン成功のメッセージを1.5秒見せた後、機密ページへ遷移
            setTimeout(() => {
                window.location.href = 'secure/secret.html';
            }, 1500);
        } else {
            showMessage(result.detail, true);
        }
        
    } catch (error) {
        console.error(error);
        showMessage(error.message || "ログイン検証中にエラーが発生しました", true);
    }
}