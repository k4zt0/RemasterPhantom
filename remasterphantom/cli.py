"""RemasterPhantom CLI.

사용 예:
  python -m remasterphantom.cli arm ./protected        # 보호 개시
  python -m remasterphantom.cli scan ./protected       # 스캔 + 자동 대응
  python -m remasterphantom.cli decrypt ./protected    # 전체 복호화
  python -m remasterphantom.cli status                 # 상태 확인
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agents.orchestrator import build_default


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="remasterphantom",
                                     description="칸네리 기반 파일 시그니처 보호 에이전트")
    parser.add_argument("--root", default="./rp_state", help="상태/키 디렉터리")
    parser.add_argument("--no-llm", action="store_true", help="LLM 로드 생략 (규칙 폴리백)")
    parser.add_argument("--model", default=None, help="HF 모델 ID")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_arm = sub.add_parser("arm", help="보호 개시")
    p_arm.add_argument("target")
    p_scan = sub.add_parser("scan", help="스캔 및 자동 대응")
    p_scan.add_argument("target")
    p_dec = sub.add_parser("decrypt", help="전체 복호화")
    p_dec.add_argument("target")
    sub.add_parser("status", help="상태 확인")

    args = parser.parse_args(argv)
    kw = {"load_llm": not args.no_llm}
    if args.model:
        kw["model_id"] = args.model
    orch = build_default(args.root, **kw)

    if args.cmd == "arm":
        out = orch.arm(args.target)
    elif args.cmd == "scan":
        out = orch.scan_and_respond(args.target)
    elif args.cmd == "decrypt":
        out = orch.decrypt_all(args.target)
    elif args.cmd == "status":
        out = orch.status()
    else:
        parser.error("unknown command")
        return 2

    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
