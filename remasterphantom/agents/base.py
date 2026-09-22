"""LLM 자문 계층.

학습된 RemasterPhantom 모델(Llama-3.2-1B LoRA)이 있으면 그것으로 사고 분류와
대응 제안을 생성하고, 모델이 없거나 로드 실패 시 규칙 기반 폴리백으로 응답한다.
보안 연산(암호화/복호화/회전) 자체는 항상 결정론적 코드가 수행하며, LLM은
'해석과 판단'을 담당한다.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_MODEL = "k4zt0/RemasterPhantom"  # HuggingFace 저장소
BASE_MODEL = "meta-llama/Llama-3.2-1B-Instruct"

# 규칙 기반 폴리백 응답 (모델 미탑재 시에도 에이전트가 동작하게)
_FALLBACK_ADVISORIES = {
    "ransomware": ("랜섬웨어 징후: 매직 바이트 대량 파괴. Phantom 프로토콜 발동 — "
                   "격리→락다운→회전→재카나리 순서로 대응하고, 감사 로그를 남기세요."),
    "canary_tampered": ("카나리 무결성 붕괴: 변조된 파일을 신뢰하지 말고 격리한 뒤 "
                        "MASTER CANARY를 회전해 전체 재보호하세요."),
    "baseline_tampered": ("기준선 변조는 전면 침입 신호입니다. 즉시 락다운하고 "
                          "MASTER CANARY를 회전한 뒤 기준선을 재구성하세요."),
    "tls_breach": ("TLS 자료 래핑 해제 실패: 개인키 유출을 가정하고 MASTER CANARY를 "
                   "회전해 새 키로 TLS 자료를 재래핑하세요."),
    "clean": ("이상 징후 없음. 정기적 스냅샷과 기준선 갱신을 유지하세요."),
}


class LLMAdvisor:
    """학습된 모델 기반 자문가. 실패 시 규칙 기반 폴리백."""

    def __init__(self, model_id: str = DEFAULT_MODEL, device: str = "auto",
                 load_model: bool = True):
        self.model_id = model_id
        self.device = device
        self._tokenizer = None
        self._model = None
        if load_model:
            self._try_load()

    def _try_load(self) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            from peft import PeftModel

            tok = AutoTokenizer.from_pretrained(self.model_id)
            try:
                model = AutoModelForCausalLM.from_pretrained(
                    self.model_id, torch_dtype=torch.float16,
                    low_cpu_mem_usage=True)
            except OSError:
                # 어댑터만 있는 경우 베이스 모델에 결합
                base = AutoModelForCausalLM.from_pretrained(
                    BASE_MODEL, torch_dtype=torch.float16,
                    low_cpu_mem_usage=True)
                model = PeftModel.from_pretrained(base, self.model_id)
            if self.device == "auto":
                if torch.backends.mps.is_available():
                    model = model.to("mps")
            elif self.device != "cpu":
                model = model.to(self.device)
            model.eval()
            self._tokenizer, self._model = tok, model
        except Exception:
            self._tokenizer = self._model = None

    @property
    def ready(self) -> bool:
        return self._model is not None

    def advise(self, situation: str, context: dict | None = None,
               max_new_tokens: int = 256) -> str:
        """상황 설명 → 모델이 분류·대응 제안을 생성. 실패 시 규칙 폴리백."""
        if self.ready:
            try:
                return self._generate(situation, context or {}, max_new_tokens)
            except Exception:
                pass
        return self._rule_fallback(situation)

    def _generate(self, situation: str, context: dict, max_new_tokens: int) -> str:
        import torch
        ctx = json.dumps(context, ensure_ascii=False)[:1500]
        messages = [
            {"role": "system", "content":
             "You are RemasterPhantom, a file-signature defense analyst. "
             "Classify the incident and give a concise response playbook in Korean."},
            {"role": "user", "content": f"상황: {situation}\n맥락: {ctx}"},
        ]
        prompt = self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True)
        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(**inputs, max_new_tokens=max_new_tokens,
                                       do_sample=False, temperature=None, top_p=None)
        text = self._tokenizer.decode(out[0][inputs["input_ids"].shape[1]:],
                                      skip_special_tokens=True)
        return text.strip()

    def _rule_fallback(self, situation: str) -> str:
        s = situation.lower()
        if "baseline" in s:
            return _FALLBACK_ADVISORIES["baseline_tampered"]
        if "tls" in s or "래핑 해제" in s:
            return _FALLBACK_ADVISORIES["tls_breach"]
        if "카나리" in s or "canary" in s:
            return _FALLBACK_ADVISORIES["canary_tampered"]
        if "ransomware" in s or "tampered" in s or "파괴" in s:
            return _FALLBACK_ADVISORIES["ransomware"]
        return _FALLBACK_ADVISORIES["clean"]
