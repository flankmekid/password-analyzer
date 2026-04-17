# password-analyzer

- a cli tool that checks how strong a password actually is, not just whether it has an uppercase letter and a symbol. uses entropy estimation, pattern detection, and real data from hibp.

## features

- entropy scoring with pattern-based penalties (dictionary words, keyboard walks, repeated chars, dates, l33tspeak)
- [haveibeenpwned](https://haveibeenpwned.com/) breach check, password always stays local.
- crack time estimates for online and offline attack scenarios
- color-coded output with a visual score bar
- interactive mode with hidden input (password is not displayed while typing)
- `--no-hibp` flag for offline use

## installation

```bash
git clone https://github.com/yourusername/password-analyzer
cd password-analyzer
```

no external dependencies, requires python 3.6+.

## usage

```bash
# analyze a single password
python analyzer.py mysupersecretpassword

# analyze a passphrase
python analyzer.py correct horse battery staple

# verbose output
python analyzer.py -v p@ssw0rd

# skip breach check (offline / faster)
python analyzer.py --no-hibp mypassword

# interactive mode
python analyzer.py
```

## disclaimer

this tool provides an **approximation** of password strength. it does not model all real-world attack strategies and should not be used as a sole security guarantee.

## how it works

### entropy

password strength is measured in **bits** of entropy using the formula:

```
H = L * log2(N)
```

where `L` is the password length and `N` is the size of the character pool used (lowercase = 26, + uppercase = 52, + digits = 62, + symbols ~= 82).
- note: `aaaaaaaaaaaaa` scores high by the formula but is obviously terrible, adding pattern penalties fixes this issue.

### pattern penalties

each detected pattern reduces the effective entropy via a penalty factor:

```
H_effective = H * (1 - penalty_factor)
```

pattern -> penalty
- dictionary words -> 85%
- keyboard walk -> 50%
- repeated characters -> 50%
- sequential characters -> 50%
- date pattern -> 30%

penalties stack and are capped at 97% reduction.

### crack time estimation

crack time is calculated from effective entropy against three attacker scenarios:

scenario -> guesses/sec
- online attack (rate limited) -> 10
- offline slow hash (bcrypt) -> 10,000
- offline fast hash (md5) -> 10,000,000,000

### haveibeenpwned breach check

uses the hibp [range api](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) with k-anonymity:

1. the password is hashed with sha-1
2. only the **first 5 characters** of the hash are sent to the api
3. hibp returns all matching hash suffixes
4. the full hash is matched **locally**

### wordlists

a wordlist of the most used 10k words in the english language is included (courtesy of https://github.com/first20hours/google-10000-english/), you can add any .txt wordlist inside the folder and the program will check for it.