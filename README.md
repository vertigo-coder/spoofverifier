# spoofverifier

a python tool to check if a domain is vulnerable to email spoofing. it queries dns for dmarc, spf, and dkim records and reports if the domain is protected or vulnerable.

## how it works

the tool checks for email authentication records in order:

- checks for a dmarc policy of `quarantine` or `reject`. if found, the domain is safe.
- if not, checks for an spf record. if found, the domain is safe.
- if not, checks for a dkim record using common selectors. if found, the domain is safe.
- if none are found, the domain is vulnerable.

## usage

```bash
python3 -m spoofverifier domains.csv
```

provide a csv file with a list of domains (one per row, or in the second column).
