import math
import re
import argparse
import os
import hashlib
import urllib.request
import getpass

# character pool
def charset_size(password):
    size = 0
    if re.search(r'[a-z]', password): size += 26
    if re.search(r'[A-Z]', password): size += 26
    if re.search(r'[0-9]', password): size += 10
    if re.search(r'[^a-zA-Z0-9]', password): size += 20
    return size

# initial entropy (H)
def raw_entropy(password):
    n = charset_size(password)
    l = len(password)
    if n == 0 or l == 0:
        return 0
    return l * math.log2(n)

# load wordlists
def load_wordlists(folder='wordlists'):
    combined = set()
    if not os.path.exists(folder):
        return combined
    for filename in os.listdir(folder):
        if filename.endswith('.txt'):
            path = os.path.join(folder, filename)
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                combined.update(line.strip().lower() for line in f if line.strip())
    return combined

WORDLIST = load_wordlists()

def normalize_leet(password):
    table = {'@': 'a', '$': 's', '3': 'e', '1': 'i', '0': 'o', '!': 'i'}
    return ''.join(table.get(c, c) for c in password.lower())

def has_dictionary_words(password, wordlist, min_word_len=4):
    pw = password.lower()
    pw_norm = normalize_leet(password)
    for word in wordlist:
        if len(word) >= min_word_len and (word in pw or word in pw_norm):
            return True
    return False

# pattern detection
keyboard_rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbn', '1234567890']

def detect_patterns(password):
    found = []
    pw_lower = password.lower()

    # wordlist check
    if WORDLIST and has_dictionary_words(password, WORDLIST):
        found.append('dictionary words')

    # keyboard walk
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            seq = row[i:i+3]
            if seq in pw_lower or seq[::-1] in pw_lower:
                found.append('keyboard walk')
                break

    # repeated characters
    if re.search(r'(.)\1{2,}', password):
        found.append('repeated characters')

    # sequential characters
    for i in range(len(password) - 2):
        a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
        if (b - a == 1 and c - b == 1) or (b - a == -1 and c - b == -1):
            found.append('sequential characters')
            break

    # date patterns
    if re.search(r'(19|20)\d{2}|(\d{2}[/-]\d{2}[/-]\d{2,4})|\b\d{8}\b', password):
        found.append('date pattern')

    return list(dict.fromkeys(found))

# penalty calculations based on detected patterns
penalties = {
    'dictionary words': 0.85,
    'keyboard walk': 0.50,
    'repeated characters': 0.50,
    'sequential characters': 0.50,
    'date pattern': 0.30,
}

def effective_entropy(password):
    raw = raw_entropy(password)
    patterns = detect_patterns(password)
    total_penalty = min(sum(penalties[p] for p in patterns), 0.97)
    return raw * (1 - total_penalty), patterns

# crack time estimates based on entropy and attack rates
rates = {
    'online, throttled': 10,
    'offline, slow hash': 10_000,
    'offline, fast hash': 10_000_000_000,
}

def format_time(seconds):
    if seconds < 1:            return 'instantly'
    elif seconds < 60:         return f'{seconds:.0f} seconds'
    elif seconds < 3600:       return f'{seconds/60:.0f} minutes'
    elif seconds < 86400:      return f'{seconds/3600:.0f} hours'
    elif seconds < 31536000:   return f'{seconds/86400:.0f} days'
    elif seconds < 3.15e9:     return f'{seconds/31536000:.0f} years'
    else:                      return 'centuries...'

def crack_times(entropy):
    results = {}
    for name, rate in rates.items():
        seconds = (2 ** entropy) / rate / 2  # average case
        results[name] = format_time(seconds)
    return results

# scoring
def score(entropy):
    if entropy < 25:  return 0, 'very weak', '\033[91m'
    elif entropy < 40: return 1, 'weak',      '\033[91m'
    elif entropy < 55: return 2, 'fair',      '\033[93m'
    elif entropy < 70: return 3, 'strong',    '\033[92m'
    else:              return 4, 'very strong','\033[92m'

def score_bar(s, total=4):
    filled = '█' * s
    empty = '░' * (total - s)
    return f'[{filled}{empty}] '

RESET = '\033[0m'

def check_hibp(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        with urllib.request.urlopen(url, timeout=3) as res:
            hashes = res.read().decode()
        for line in hashes.splitlines():
            h, count = line.split(':')
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None

# output
def analyze(password, verbose=False, no_hibp=False):
    raw = raw_entropy(password)
    eff, patterns = effective_entropy(password)
    s, label, color = score(eff)

    breaches = None
    if not no_hibp:
        breaches = check_hibp(password)

    # adjust score based on breach and warnings
    if breaches:
        s, label, color = 0, 'very weak', '\033[91m'
    elif len(patterns) >= 2:
        s = max(0, s - 1)
        labels = ['very weak', 'weak', 'fair', 'strong', 'very strong']
        colors = ['\033[91m', '\033[91m', '\033[93m', '\033[92m', '\033[92m']
        label = labels[s]
        color = colors[s]

    print(f"\npassword : {'*' * len(password)}")
    print(f"strength : {color}{score_bar(s)}{label}{RESET} ({s}/4)")
    print(f"entropy  : {eff:.1f} bits  (raw: {raw:.1f})")

    print(f"\ncrack time estimates:")
    for name, t in crack_times(eff).items():
        print(f"  {name}: {t}")

    if patterns:
        print(f"\nwarnings:")
        for p in patterns:
            print(f"  ⚠️ {p}")

    if not no_hibp:
        if breaches is None:
            print("\n  ⚠️ hibp check failed")
        elif breaches == 0:
            print("\n  ✔️ not found in any known breaches")
        else:
            print(f"\n  ⚠️ found in {breaches:,} breaches, do not use! ⚠️")

    if verbose:
        print(f"\ndetails:")
        print(f"  length  : {len(password)}")
        print(f"  charset : {charset_size(password)} characters")

# cli interface
def main():
    parser = argparse.ArgumentParser(description='password strength analyzer')
    parser.add_argument('password', nargs='*', help='password to analyze')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--no-hibp', action='store_true', help='skip breach database check')
    args = parser.parse_args()

    if args.password:
        analyze(' '.join(args.password), args.verbose, args.no_hibp)
    else:
        try:
            while True:
                pw = getpass.getpass('\n> ')
                if pw:
                    analyze(pw, args.verbose, args.no_hibp)
        except KeyboardInterrupt:
            print('\ndone.')

if __name__ == '__main__':
    main()