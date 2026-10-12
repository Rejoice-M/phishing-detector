# scoring.py
# Purpose: turns the list of Findings into one overall risk score.
#   - calculate_score(): adds up the points from the checks that triggered, capped at 100
#   - risk_level(): labels the score low (under 20), medium (20-49) or high (50 and up)
# The point values are set by each check in url_analyzer.py. They are first guesses
# that we tune once all the checks exist.

"""
The scoring (scoring.py) adds up the points from the checks that triggered, 
caps the total at 100, and labels it low, medium, or high. The point values 
are first guesses, and tune them once more checks exist.
"""
from app.analyzers.url_analyzer import Finding


def calculate_score(findings: list[Finding]) -> int:
    total = sum(f.points for f in findings if f.triggered)
    return min(total, 100)


def risk_level(score: int) -> str:
    if score < 20:
        return "low"
    if score < 50:
        return "medium"
    return "high"
