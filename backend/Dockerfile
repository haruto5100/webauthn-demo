# ベースとなる軽量なPython環境
FROM python:3.11-slim

# コンテナ内の作業場所を /app に設定
WORKDIR /app

# 道具のリストをコンテナ内にコピーして、インストールを実行
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# FastAPIのプログラム（main.py）をコピー
COPY main.py .

# コンテナが立ち上がった時に実行されるコマンド（0.0.0.0で待ち受けるのがDockerの鉄則です）
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]