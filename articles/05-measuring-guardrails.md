# Guardrails Are a Layer, Not a Wall: How to Measure Them Honestly

*"Blocks 95% of prompt injections" is a sentence that sounds like a measurement and is not one yet.*

Guardrail products for LLM applications, such as input classifiers, output filters, and prompt-injection detectors, are useful. They are also sold with numbers that are easy to misread. If you are deciding whether to deploy one, or building your own, you need to know how to read those numbers and how to produce your own.

Simon Willison has been blunt on this point: a filter that stops 95% of attacks is a failing grade, because an attacker only needs the 5% that gets through. That is the right instinct, and this post turns it into a method: what to measure, how much data you need, why retries change the picture, and how to report results without fooling yourself.

## First question: 95% of what?

A block rate is a ratio, and a ratio is only as meaningful as its denominator.

- **Which attacks?** A detector trained on a public dataset will do well on that dataset's style. Attacks written for your application, in your domain's vocabulary, hidden in your document formats, will look different.
- **Were the test attacks seen during development?** Anything the vendor tuned against is contaminated. Ask for results on a held-out set.
- **Was the attacker adaptive?** A static list of attack strings measures the filter against yesterday's attackers. A real attacker reads the refusal, rewrites, and tries again.
- **What was the target?** Blocking a harmful-sounding prompt is a different task from catching an instruction hidden in a web page the agent retrieved. See [indirect injection](01-lethal-trifecta.md) for why the second matters more for agents.

A single headline number hides all of this. Ask for the breakdown.

## Measure both sides

Every guardrail has two error rates, and you need both.

| Metric | Definition | Why it matters |
|---|---|---|
| **Miss rate** | Attacks that were *not* blocked, out of all attacks | The security number |
| **False block rate** | Benign requests that *were* blocked, out of all benign requests | The usability number |

A guardrail that blocks everything has a miss rate of zero and is useless. Without a false block rate measured on **your own realistic benign traffic**, a low miss rate means nothing. Teams tend to measure the first and discover the second from user complaints.

Also record latency and cost per request. A filter that adds a second to every call, or doubles your token bill, changes what you can ship.

And report **per category** instead of one aggregate. Direct injection, indirect injection through documents, and encoded or obfuscated payloads usually behave very differently, and an average hides the weak one.

## Sample size: zero misses is not zero risk

Suppose you test a guardrail on 50 attacks and it misses none. Is the miss rate zero? No. You have shown it did not miss in 50 tries. Statistically, the true miss rate could plausibly be several percent.

A Wilson score interval puts numbers on this. For 0 misses:

| Attacks tested | 95% upper bound on the true miss rate |
|---|---|
| 10 | 27.8% |
| 50 | 7.1% |
| 200 | 1.9% |

So "we tested 50 attacks and it caught all of them" supports only "the miss rate is probably under about 7%." If your risk tolerance is 1%, you need hundreds of well-chosen attacks, not dozens. The same logic applies to the benign set: a false block rate measured on 20 requests is mostly noise.

## Retries change the math

The miss rate describes one attempt. Attackers do not make one attempt.

If each attempt independently gets through 5% of the time:

| Attempts | Chance at least one gets through |
|---|---|
| 1 | 5.0% |
| 10 | 40.1% |
| 20 | 64.2% |

Even a 1% miss rate reaches 63.4% over 100 attempts. These figures assume independent attempts, which is a simplification. In practice an adaptive attacker uses the refusal as feedback, so attempts are *not* independent and the real situation is usually worse than this arithmetic suggests. The point is the direction: a per-attempt miss rate that sounds small is not a small probability of eventual compromise.

This is the strongest argument for treating a guardrail as one layer. It lowers the probability of each attempt succeeding. It does not change what a successful attempt can do. That is decided by permissions, isolation, egress control, and human approval, as covered in the [lethal trifecta](01-lethal-trifecta.md) article.

## Keep the evaluation honest

- **Hold out data.** Keep a test set that nobody tunes against, and refresh it. Attacks that were in the development set measure memory.
- **Use your own benign traffic.** Sample real, anonymized requests. A generic benign set will understate how often the filter blocks legitimate work in your domain.
- **Test the whole path.** Include documents, tool results, and retrieved content, not only the chat box. Most agent exposure comes from those channels.
- **Try an adaptive attacker.** Give someone the time to iterate against the filter and record how many attempts it takes, not only whether it eventually fails.
- **Pin and record everything.** Model and guardrail versions, thresholds, prompts, and dates. Results from last quarter's version say little about this quarter's.
- **Repeat non-deterministic runs.** If a model is part of the pipeline, run each case several times and report the rate.
- **Retest on change.** New model, new threshold, new attack technique: rerun.

## A small reporting script

This script takes one JSON object per line with `category`, `label` (`attack` or `benign`) and `blocked`, and prints miss rate and false block rate per category with 95% intervals:

```python
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def report(rows: list[dict]) -> None:
    """rows: {"category": str, "label": "attack" | "benign", "blocked": bool}"""
    groups = defaultdict(lambda: {"attack": [0, 0], "benign": [0, 0]})
    for r in rows:
        bucket = groups[r["category"]][r["label"]]
        bucket[1] += 1
        # for attacks we count misses (not blocked); for benign we count false blocks
        bucket[0] += int(not r["blocked"]) if r["label"] == "attack" else int(r["blocked"])
    print(f"{'category':<22}{'miss rate (attacks)':<30}{'false block rate (benign)':<30}")
    for cat in sorted(groups):
        cells = []
        for label in ("attack", "benign"):
            k, n = groups[cat][label]
            lo, hi = wilson(k, n)
            cells.append(f"{k}/{n} = {k / n:.1%} [{lo:.1%}, {hi:.1%}]" if n else "no data")
        print(f"{cat:<22}{cells[0]:<30}{cells[1]:<30}")


if __name__ == "__main__":
    report([json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()])
```

Here is its output on a **synthetic** dataset generated with a random number generator, included only to show the format. It is not a measurement of any product:

```text
category              miss rate (attacks)           false block rate (benign)
direct injection      2/60 = 3.3% [0.9%, 11.4%]     7/120 = 5.8% [2.9%, 11.6%]
encoded / obfuscated  12/30 = 40.0% [24.6%, 57.7%]  2/30 = 6.7% [1.8%, 21.3%]
indirect (documents)  17/40 = 42.5% [28.5%, 57.8%]  6/120 = 5.0% [2.3%, 10.5%]
```

Notice how wide the intervals are at these sample sizes, and how a single aggregate over all rows would hide the difference between the first row and the others. That is the argument for reporting this way.

## What to do with the numbers

1. **Decide your tolerance first**, in terms of impact: what is the worst thing a successful injection can do here? If the answer is "send private data out" or "run a destructive action," no miss rate is low enough. Fix the architecture.
2. **Use the guardrail to reduce volume and noise**, and for detection: a blocked or flagged attempt is a signal worth alerting on, as in the fallback metrics from the [SOC triage post](02-your-logs-can-talk.md).
3. **Compare options on the same data.** Run candidates against one held-out set, with the same benign traffic, and compare miss rate, false block rate, latency, and cost together.
4. **Record the limits** next to the results: dataset, size, interval, date, versions.

## Takeaways

1. A block rate without a dataset, sample size, and false positive rate is marketing, not measurement.
2. Measure miss rate and false block rate, per category, on your own traffic.
3. Zero misses in 50 tests only bounds the miss rate below roughly 7%. Use intervals.
4. Retries compound. A small per-attempt miss rate is not a small chance of eventual compromise.
5. Guardrails lower probability. Architecture limits impact. You need both.

If you want this as a checklist for reviews, the [`ai-agent-defense`](https://github.com/WaiperOK/ai-agent-security-skills/blob/main/skills/ai-agent-defense/SKILL.md) and [`ai-agent-redteam`](https://github.com/WaiperOK/ai-agent-security-skills/blob/main/skills/ai-agent-redteam/SKILL.md) skills in the same repository cover where guardrails fit and how to test them.

## References

- Simon Willison, ["The lethal trifecta for AI agents"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/): LLM01 Prompt Injection
- [Binomial proportion confidence interval](https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval) (Wilson score interval)
