import csv
from collections import Counter

phish_dates = []
with open('data/processed/0.1.0/samples.csv', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        if row['label'] == 'phishing':
            ts = row.get('source_timestamp', '')
            if ts:
                phish_dates.append(ts[:10])

counts = Counter(phish_dates)
sorted_dates = sorted(counts.keys())
print(f'Date range: {sorted_dates[0]} to {sorted_dates[-1]}')
print(f'Total unique dates: {len(sorted_dates)}')

year_counts = Counter(d[:4] for d in phish_dates)
print('\n=== Distribution by year ===')
for year in sorted(year_counts):
    print(f'  {year}: {year_counts[year]}')

cutoff = '2025-06-01'
before = sum(counts[d] for d in sorted_dates if d < cutoff)
after = sum(counts[d] for d in sorted_dates if d >= cutoff)
print(f'\n=== Cutoff analysis ===')
print(f'  Phishing < {cutoff}: {before} ({before/len(phish_dates)*100:.1f}%)')
print(f'  Phishing >= {cutoff}: {after} ({after/len(phish_dates)*100:.1f}%)')

# Show monthly for 2025
print('\n=== 2025 monthly ===')
recent = [(d, counts[d]) for d in sorted_dates if d >= '2025-01-01']
months = Counter(d[:7] for d, _ in recent)
for m in sorted(months):
    print(f'  {m}: {months[m]}')
