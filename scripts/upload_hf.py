"""HuggingFace 업로드 스크립트.

사전: `hf auth login` (또는 HF_TOKEN 환경변수) — 게이트 여부와 무관하게
저장소 생성/업로드에는 토큰이 필요하다.

업로드 대상:
  - outputs/RemasterPhantom-merged  (병합 모델)
  - outputs/remasterphantom-lora    (LoRA 어댑터)
  - data/remasterphantom_sft.jsonl  (SFT 데이터셋)
"""

from __future__ import annotations

import os
import sys

MERGED_DIR = os.environ.get("MERGED_DIR", "outputs/RemasterPhantom-merged")
ADAPTER_DIR = os.environ.get("OUTPUT_DIR", "outputs/remasterphantom-lora")
DATA_FILE = os.environ.get("DATA_PATH", "data/remasterphantom_sft.jsonl")

from huggingface_hub import HfApi, whoami  # noqa: E402


def main() -> None:
    try:
        user = whoami()["name"]
    except Exception:
        sys.exit("HF 로그인이 필요합니다: hf auth login (https://huggingface.co/settings/tokens)")

    repo_id = f"{user}/RemasterPhantom"
    api = HfApi()
    api.create_repo(repo_id, exist_ok=True)

    if os.path.isdir(MERGED_DIR):
        api.upload_folder(folder_path=MERGED_DIR, repo_id=repo_id,
                          commit_message="RemasterPhantom — merged model")
        print(f"merged model uploaded: {MERGED_DIR}")
    if os.path.isdir(ADAPTER_DIR):
        api.upload_folder(folder_path=ADAPTER_DIR, repo_id=repo_id,
                          path_in_repo="lora_adapter",
                          commit_message="RemasterPhantom — LoRA adapter")
        print(f"adapter uploaded: {ADAPTER_DIR}")
    if os.path.isfile(DATA_FILE):
        api.upload_file(path_or_fileobj=DATA_FILE,
                        path_in_repo="data/remasterphantom_sft.jsonl",
                        repo_id=repo_id, commit_message="SFT dataset")
        print(f"dataset uploaded: {DATA_FILE}")

    print(f"done: https://huggingface.co/{repo_id}")


if __name__ == "__main__":
    main()
