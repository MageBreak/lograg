#!/bin/bash
export CUDA_VISIBLE_DEVICES=1
export HF_HUB_OFFLINE=1
cd ~/projects/lograg
source ~/projects/lograg-env/bin/activate

echo "######## EMBEDDING MODEL ABLATION ########"
for m in BAAI/bge-small-en-v1.5 BAAI/bge-large-en-v1.5 Qwen/Qwen3-Embedding-4B; do
  echo ""
  echo "======== EMBED_MODEL=$m ========"
  EMBED_MODEL=$m python src/index.py    || { echo "index failed"; continue; }
  EMBED_MODEL=$m python eval/run_eval.py --ablation
  cp eval/results.json "eval/results_$(basename $m).json"
done

echo ""
echo "######## RESTORE bge-small INDEX ########"
python src/index.py

echo ""
echo "######## LOCAL MODEL ANSWERS ########"
python batch_answers.py

echo "ALL DONE"
