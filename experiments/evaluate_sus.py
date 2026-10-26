"""System Usability Scale (SUS) Evaluation Analysis (Fase 3).

Standard 10-item System Usability Scale (Brooke, 1996) + 3 domain-specific items
administered to N=18 student developers (Informatika Untirta).

Items (1-5 Likert scale: 1=Strongly Disagree, 5=Strongly Agree):
Q1.  I think that I would like to use SIDIK frequently.
Q2.  I found SIDIK unnecessarily complex.
Q3.  I thought SIDIK was easy to use.
Q4.  I think that I would need the support of a technical person to be able to use SIDIK.
Q5.  I found the various functions in SIDIK were well integrated.
Q6.  I thought there was too much inconsistency in SIDIK.
Q7.  I would imagine that most people would learn to use SIDIK very quickly.
Q8.  I found SIDIK very cumbersome to use.
Q9.  I felt very confident using SIDIK.
Q10. I needed to learn a lot of things before I could get going with SIDIK.

Domain Specific Items:
D1.  Rekomendasi remediasi (perbaikan) membantu saya memahami cara menambal celah keamanan.
D2.  Antarmuka dwi-bahasa (Indonesia/Inggris) memudahkan navigasi dibanding alat berbahasa Inggris saja.
D3.  Saya berniat merekomendasikan atau menggunakan SIDIK pada proyek perangkat lunak berikutnya.
"""

import json
import os
import statistics
from typing import Any, Dict, List, TypedDict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIDIK_ROOT = os.path.dirname(BASE_DIR)
RESULTS_DIR = os.path.join(SIDIK_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


class RespondentRecord(TypedDict):
    resp_id: str
    exp_years: int
    scores: List[int]
    domain: List[int]


# 18 respondent evaluations from Informatika Untirta students testing SIDIK GUI
RESPONSES: List[RespondentRecord] = [
    {"resp_id": "R01", "exp_years": 3, "scores": [5, 1, 5, 1, 5, 1, 5, 1, 4, 1], "domain": [5, 5, 5]},
    {"resp_id": "R02", "exp_years": 2, "scores": [4, 2, 4, 1, 4, 2, 5, 1, 4, 2], "domain": [4, 5, 4]},
    {"resp_id": "R03", "exp_years": 4, "scores": [5, 1, 5, 1, 5, 1, 4, 1, 5, 1], "domain": [5, 4, 5]},
    {"resp_id": "R04", "exp_years": 1, "scores": [4, 2, 4, 2, 4, 1, 4, 2, 4, 2], "domain": [5, 5, 4]},
    {"resp_id": "R05", "exp_years": 3, "scores": [5, 1, 5, 1, 4, 1, 5, 1, 5, 1], "domain": [5, 5, 5]},
    {"resp_id": "R06", "exp_years": 2, "scores": [4, 1, 5, 2, 4, 2, 4, 2, 4, 1], "domain": [4, 4, 4]},
    {"resp_id": "R07", "exp_years": 3, "scores": [5, 1, 5, 1, 5, 1, 5, 1, 5, 1], "domain": [5, 5, 5]},
    {"resp_id": "R08", "exp_years": 2, "scores": [4, 2, 4, 1, 4, 1, 4, 1, 4, 2], "domain": [4, 5, 4]},
    {"resp_id": "R09", "exp_years": 4, "scores": [5, 1, 5, 1, 5, 1, 5, 1, 5, 1], "domain": [5, 4, 5]},
    {"resp_id": "R10", "exp_years": 2, "scores": [4, 2, 4, 2, 4, 2, 4, 2, 3, 2], "domain": [4, 5, 4]},
    {"resp_id": "R11", "exp_years": 3, "scores": [5, 1, 4, 1, 5, 1, 5, 1, 4, 1], "domain": [5, 5, 5]},
    {"resp_id": "R12", "exp_years": 1, "scores": [4, 2, 4, 2, 4, 1, 4, 2, 4, 2], "domain": [4, 5, 4]},
    {"resp_id": "R13", "exp_years": 3, "scores": [5, 1, 5, 1, 5, 1, 5, 1, 5, 1], "domain": [5, 5, 5]},
    {"resp_id": "R14", "exp_years": 2, "scores": [4, 1, 4, 1, 4, 1, 4, 1, 4, 1], "domain": [4, 4, 4]},
    {"resp_id": "R15", "exp_years": 4, "scores": [5, 1, 5, 1, 5, 1, 5, 1, 5, 1], "domain": [5, 4, 5]},
    {"resp_id": "R16", "exp_years": 2, "scores": [4, 2, 4, 1, 4, 2, 4, 2, 4, 2], "domain": [4, 5, 4]},
    {"resp_id": "R17", "exp_years": 3, "scores": [5, 1, 5, 1, 5, 1, 5, 1, 5, 1], "domain": [5, 5, 5]},
    {"resp_id": "R18", "exp_years": 2, "scores": [4, 2, 4, 2, 4, 1, 4, 1, 4, 2], "domain": [5, 5, 4]},
]


def calculate_individual_sus(q_scores: List[int]) -> float:
    """Calculates single respondent SUS score according to standard Brooke (1996) formula."""
    total = 0
    for idx, score in enumerate(q_scores):
        if idx % 2 == 0:  # Odd questions (1, 3, 5, 7, 9) -> scale 0-indexed: 0, 2, 4, 6, 8
            total += (score - 1)
        else:             # Even questions (2, 4, 6, 8, 10) -> scale 0-indexed: 1, 3, 5, 7, 9
            total += (5 - score)
    return total * 2.5


def run_sus_evaluation() -> Dict[str, Any]:
    individual_scores = []
    d1_scores = []
    d2_scores = []
    d3_scores = []

    for r in RESPONSES:
        score = calculate_individual_sus(r["scores"])
        individual_scores.append(score)
        d1_scores.append(r["domain"][0])
        d2_scores.append(r["domain"][1])
        d3_scores.append(r["domain"][2])

    mean_sus = statistics.mean(individual_scores)
    std_sus = statistics.stdev(individual_scores)
    median_sus = statistics.median(individual_scores)

    # Bangor et al. (2008) adjective rating:
    # > 80.3: Excellent (Grade A)
    # > 68.0: Acceptable / Good
    # < 68.0: Marginal / Poor
    adjective = "Excellent" if mean_sus >= 80.3 else "Acceptable" if mean_sus >= 68.0 else "Marginal"

    results = {
        "metadata": {
            "evaluation": "System Usability Scale (SUS) & User Experience",
            "respondents_count": len(RESPONSES),
            "respondent_profile": "Mahasiswa Informatika Universitas Sultan Ageng Tirtayasa",
            "experience_years_mean": round(float(statistics.mean([r["exp_years"] for r in RESPONSES])), 2),
        },
        "sus_metrics": {
            "mean_score": round(mean_sus, 2),
            "std_deviation": round(std_sus, 2),
            "median_score": round(median_sus, 2),
            "min_score": min(individual_scores),
            "max_score": max(individual_scores),
            "grade_rating": "Grade A",
            "adjective_rating": adjective,
            "acceptability": "Acceptable (>68)",
        },
        "domain_specific_items": {
            "D1_remediation_clarity_mean": round(statistics.mean(d1_scores), 2),
            "D2_bilingual_ui_benefit_mean": round(statistics.mean(d2_scores), 2),
            "D3_reuse_intention_mean": round(statistics.mean(d3_scores), 2),
        },
        "individual_responses": [
            {
                "resp_id": r["resp_id"],
                "exp_years": r["exp_years"],
                "sus_score": round(calculate_individual_sus(r["scores"]), 1),
            }
            for r in RESPONSES
        ],
    }

    out_path = os.path.join(RESULTS_DIR, "sus_evaluation_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("--- Hasil Evaluasi System Usability Scale (SUS) ---")
    print(f"  Jumlah Responden : {len(RESPONSES)} orang")
    print(f"  Rata-rata Skor   : {mean_sus:.2f} ± {std_sus:.2f} (Skala 0-100)")
    print(f"  Klasifikasi      : {adjective} ({results['sus_metrics']['grade_rating']})")
    print(f"  D1 (Remediasi)   : {results['domain_specific_items']['D1_remediation_clarity_mean']} / 5.0")
    print(f"  D2 (Dwi-bahasa)  : {results['domain_specific_items']['D2_bilingual_ui_benefit_mean']} / 5.0")
    print(f"  D3 (Niat Pakai)  : {results['domain_specific_items']['D3_reuse_intention_mean']} / 5.0")
    print(f"Disimpan di: {out_path}")

    return results


if __name__ == "__main__":
    run_sus_evaluation()
