# Proof of Transaction

Proof of Transaction is one executable Proof Concept inside TohuPono. It is not payment processing, a wallet, a registry lookup, or legal validation.

## Exact Claim

The proof packet contains canonical declared transaction envelopes binding the recorded subject digest to declared participants and transaction metadata, and the retained declarations are internally consistent.

## What It Does Not Prove

Proof of Transaction does not prove that a transaction occurred, that payment occurred, that goods, files, rights, or value were delivered, that a participant is a verified person or organisation, that participants consented, that any participant had authority, ownership before or after the declaration, transfer of ownership, contractual formation, legal validity, enforceability, authenticity, authorship, external registration, external timestamp validity, or completeness of transaction history.

## Descriptor Schema

Transaction descriptors are strict JSON:

```json
{
  "schema_version": "tohupono.transaction_descriptor.v1",
  "transaction_type": "transfer",
  "participants": [
    {
      "role": "sender",
      "namespace": "local",
      "identifier": "party-a"
    },
    {
      "role": "receiver",
      "namespace": "local",
      "identifier": "party-b"
    }
  ],
  "occurred_at": null,
  "reference": null,
  "terms": {},
  "attributes": {}
}
```

Supported transaction types are `transfer`, `sale`, `gift`, `license`, `assignment`, `exchange`, and `receipt`. These are declared categories only.

Participant roles are declarative. Supported roles are `sender`, `receiver`, `buyer`, `seller`, `giver`, `recipient`, `licensor`, `licensee`, `assignor`, `assignee`, `provider`, `customer`, `witness`, and `other`. TohuPono does not verify, resolve, or contact participants.

`occurred_at`, when present, must use canonical UTC form `YYYY-MM-DDTHH:MM:SSZ`. It is declared metadata, not external timestamp evidence.

References, terms, and attributes are declarative only. TohuPono does not fetch references, execute terms, process payments, or upload transaction data.

The loader rejects duplicate JSON keys, floating-point values, non-finite numbers, excessive depth, excessive item counts, oversized descriptors, unsafe text, directories, symlinks, and material mutation during read.

## Transaction Envelope

TohuPono injects the proved subject digest. Descriptors cannot provide `subject`, `transaction_id`, `proof_id`, or `claim_id`.

The manifest transaction envelope contains:

- `transaction_id`;
- `schema_version`;
- `transaction_type`;
- `subject`;
- `participants`;
- `occurred_at`;
- `reference`;
- `terms`;
- `attributes`.

The envelope does not store descriptor paths, source paths, hostnames, usernames, operating-system timestamps, registry prose, report wording, or maturity labels.

## Transaction IDs

`transaction_id` is `txn_` plus the first 32 hexadecimal characters of SHA-256 over the canonical transaction body excluding `transaction_id`.

Changing the subject digest, transaction type, participants, occurred time, reference, terms, or attributes changes the transaction ID. Descriptor paths, descriptor ordering, participant input ordering, and JSON key ordering do not.

## Manifest and Claim Linkage

A transaction proof includes a top-level `transactions` section only when `--concept transaction` is selected. The section stores `schema_version`, `transaction_count`, and canonical transaction envelopes sorted by `transaction_id`.

The `transaction` Proof Concept claim stores the transactions schema version, sorted transaction IDs, and the subject digest. Verification fails if the claim and stored transactions section diverge.

## CLI

```bash
python -m tohupono prove ./file.bin --concept transaction --transaction-json ./transfer.json
python -m tohupono transaction validate ./transfer.json
python -m tohupono transaction inspect ./proof_packet
```

Supplying `--transaction-json` without `--concept transaction` is an input error. Selecting `transaction` without at least one descriptor is also an input error. Transaction is not part of the default concept set; default proof generation remains `existence` and `integrity`.

## Privacy

Transaction descriptors and manifest envelopes may expose participants, references, terms, and attributes. Do not place credentials, private keys, secrets, payment credentials, unnecessary personal information, or sensitive contractual information in transaction descriptors.

## Legacy Behavior

Packets without a `transactions` section or explicit `transaction` Proof Concept remain loadable, verifiable, auditable, reportable, proof-ID-compatible, and signature-compatible. TohuPono does not infer Transaction from Records, Custody, Provenance, or older metadata fields.
