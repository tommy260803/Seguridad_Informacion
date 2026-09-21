import json
import sys
sys.stdout.reconfigure(encoding="utf-8")
results = json.loads(open("artifacts/evaluation/llm_evaluation_results.json", encoding="utf-8").read())
successful = [r for r in results if r["llm_prob"] is not None]
print("=== Successful LLM predictions ===")
for r in successful:
    label = "PHISH" if r["label"] == 1 else "LEGIT"
    prob = r["llm_prob"]
    pred = "PHISH" if prob >= 0.5 else "LEGIT"
    correct = "OK" if label == pred else "WRONG"
    m0 = r["m0_prob"]
    url = r["url"][:70]
    print(f"  [{correct:6}] {label} LLM={prob:.3f} M0={m0:.3f} | {url}")
    if r.get("llm_brand"):
        print(f"           brand={r['llm_brand']}, rec={r.get('llm_recommendation','?')}")
