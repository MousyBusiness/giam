# giam

A CLI tool to manage IAM policies for Google Cloud Platform, specifically for granting temporary roles to users.

## Usage

```bash
giam grant -r <role> -m <member> -d <duration>
```

## Example

```bash
giam grant -r roles/iam.serviceAccountUser -m user@example.com -d 1h
```
