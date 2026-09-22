"""RemasterPhantom — 카나리 기반 파일 시그니처 보호 LLM 에이전트 프레임워크.

구성:
- signatures : 파일 시그니처(매직 바이트) DB 및 무결성 검증
- crypto     : 카나리 암호화/복호화, MASTER CANARY 루트 오브 트러스트
- defense    : 카나리 무결성 붕괴 시 Phantom 폴리백 프로토콜
- agents     : Sentinel / Canary / Master / Phantom LLM 에이전트 오케스트레이션
"""

__version__ = "0.1.0"
