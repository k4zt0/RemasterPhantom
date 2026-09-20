---
license: apache-2.0
tags:
- security
- defensive-security
- anti-ransomware
- file-integrity
- llama
base_model: meta-llama/Llama-3.2-1B-Instruct
---

# RemasterPhantom

파일 시그니처(매직 바이트) 무결성 검증, 칸네리 기반 암호화/복호화, 랜섬웨어 사고 대응, 마스터칸네리 TLS 보호를 수행하는 **방어 전용** LLM 에이전트의 자문 모델.

## 개요

Llama-3.2-1B-Instruct를 파일 시그니처 방어 전문가로 LoRA 파인튜닝한 모델이다.
[RemasterPhantom 프레임워크](https://github.com/k4zt0/RemasterPhantom)의 에이전트(Sentinel / Canary / Master / Phantom)가 사고 판단 시 이 모델을 자문가로 사용한다.

- **학습 데이터**: 5,880개 합성 지시-응답 쌍 — 매직 바이트 식별, 무결성 검증 절차, 칸네리 운영, Phantom 폴리백 플레이북, TLS 보호, 공격 요청 거부 가드레일
- **학습 방식**: LoRA (r=16, 전체 선형층), 전체 시퀀스 SFT, bf16, 3 epoch

## 사용법

```python
from remasterphantom.agents.base import LLMAdvisor
advisor = LLMAdvisor("k4zt0/RemasterPhantom")
print(advisor.advise("칸네리 무결성이 물너졌다는 신호는 무엇인가요?"))
```

## 베이스 모델

`meta-llama/Llama-3.2-1B-Instruct` — 학습 시 비게이트 미러(`unsloth/Llama-3.2-1B-Instruct`, 동일 가중치)로 실행했다.

## 한계

- 방어 분야 특화 모델로, 일반 지식은 베이스 모델 수준을 따른다.
- 공격/악성코드 관련 요청은 학습된 가드레일이 거부한다.
