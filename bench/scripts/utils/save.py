import json
import time
import os

def save_benchmark_results(all_results, summary, output_path="../results/benchmarks.json"):
    """
    Salva i risultati di tutte le iterazioni e il riepilogo in un file JSON.

    Args:
        all_results (list[dict]): Lista dei dizionari dei singoli run.
        summary (dict): Dizionario con media, deviazione standard, picco ecc.
        output_path (str): Percorso del file JSON di output.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "individual_runs": all_results,
        "summary": summary
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
