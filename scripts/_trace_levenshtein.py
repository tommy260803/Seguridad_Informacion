import sys
sys.path.insert(0, "src")
from phishguard_ml import homoglyphs as H
import inspect
print(inspect.getsource(H.levenshtein_distance))

# referencia independiente
def ref(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
    return dp[-1][-1]

cases = [("t", "microsoft"), ("a", "b"), ("ab", "cd"), ("apple", "paypal"),
         ("t", "t"), ("ly", "microsoft"), ("googlee", "google"), ("apple", "apple"),
         ("paypal", "paypal"), ("microsoft", "microsoft"), ("googlee", "google")]
print("%-12s %-12s %8s %8s" % ("s1", "s2", "actual", "ref"))
for a, b in cases:
    got, exp = H.levenshtein_distance(a, b), ref(a, b)
    flag = "OK " if got == exp else "WRONG"
    print("%-12s %-12s %8d %8d  %s" % (a, b, got, exp, flag))
