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
