"""RemasterPhantom 학습 스크립트 (노트북과 동일 파이프라인).

노트북: notebooks/train_remasterphantom.ipynb — 대화형 실행용.
본 스크립트: 로컬/백그라운드 일괄 실행용.

BASE_MODEL 환경변수로 베이스 교체 가능:
  기본값 unsloth/Llama-3.2-1B-Instruct — meta-llama/Llama-3.2-1B-Instruct와
  동일한 가중치의 비게이트 미러(게이트 통과가 어려운 환경용).
"""

from __future__ import annotations

import os
import sys

BASE_MODEL = os.environ.get(
    "BASE_MODEL", "unsloth/Llama-3.2-1B-Instruct")
DATA_PATH = os.environ.get("DATA_PATH", "data/remasterphantom_sft.jsonl")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "outputs/remasterphantom-lora")
MERGED_DIR = os.environ.get("MERGED_DIR", "outputs/RemasterPhantom-merged")
EPOCHS = int(os.environ.get("EPOCHS", "3"))
MAX_LENGTH = int(os.environ.get("MAX_LENGTH", "1024"))
SAVE_STEPS = int(os.environ.get("SAVE_STEPS", "0"))  # 0이면 epoch마다 저장

import torch
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import LoraConfig, get_peft_model
from trl import SFTConfig, SFTTrainer

device = "mps" if torch.backends.mps.is_available() else ("cuda" if torch.cuda.is_available() else "cpu")
dtype = torch.bfloat16 if device in ("mps", "cuda") else torch.float32
print(f"[cfg] base={BASE_MODEL} device={device} dtype={dtype} epochs={EPOCHS} "
      f"max_length={MAX_LENGTH} save_steps={SAVE_STEPS or 'epoch'}", flush=True)

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL, dtype=dtype, low_cpu_mem_usage=True, attn_implementation="sdpa")
model.config.use_cache = False
model.gradient_checkpointing_enable()
model = model.to(device)

ds = load_dataset("json", data_files=DATA_PATH, split="train").shuffle(seed=42)
split = ds.train_test_split(test_size=0.05, seed=42)
train_ds, eval_ds = split["train"], split["test"]
print(f"[data] train={len(train_ds)} eval={len(eval_ds)}", flush=True)

lora_cfg = LoraConfig(
    r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"])
model = get_peft_model(model, lora_cfg)
model.print_trainable_parameters()

sft_kwargs = dict(
    output_dir=OUTPUT_DIR,
    num_train_epochs=EPOCHS,
    per_device_train_batch_size=1,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=8,
    learning_rate=2e-4,
    lr_scheduler_type="cosine",
    warmup_steps=60,
    logging_steps=10,
    eval_strategy="epoch",
    bf16=(dtype == torch.bfloat16),
    max_length=MAX_LENGTH,
    packing=False,
    gradient_checkpointing=True,
    report_to="none",
    seed=42,
    dataset_num_proc=4,
)
if SAVE_STEPS > 0:
    sft_kwargs.update(save_strategy="steps", save_steps=SAVE_STEPS,
                      save_total_limit=6)
else:
    sft_kwargs.update(save_strategy="epoch")
sft_cfg = SFTConfig(**sft_kwargs)

trainer = SFTTrainer(model=model, args=sft_cfg,
                     train_dataset=train_ds, eval_dataset=eval_ds,
                     processing_class=tokenizer)
trainer.train()

trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
merged = model.merge_and_unload()
merged.save_pretrained(MERGED_DIR, safe_serialization=True)
tokenizer.save_pretrained(MERGED_DIR)
print(f"[done] adapter={OUTPUT_DIR} merged={MERGED_DIR}", flush=True)
