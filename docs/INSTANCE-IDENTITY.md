# Instance, place, class: what the chips actually give

> Measured on the evidence this repository ships: 87 genuine SEV-SNP reports (71 GCP, 16 AWS),
> the VLEK certificates the AWS run captured, and two TDREPORTs from two Intel TDX guests.
> Reproduce with `PYTHONPATH=. python3 examples/granularity.py` (output: `granularity-run.txt`);
> pinned offline in `tests/test_granularity.py`.

## The two questions the working groups leave open

draft-ietf-rats-endorsements-11, Section 4: *"The granularity at which such identifiers, and
therefore the signature-checking keys endorsed for them, apply (e.g., per instance, class, or
other claims) is out of scope of this document."*

draft-ietf-seat-use-cases-01, 4.3: Evidence bound to *"the identifier provided to the machine by
the infrastructure provider"*; 3.8.1: authorisation bound *"to that instance, rather than only to
an environment class"*. Neither says which field on real silicon can carry it.

## SEV-SNP: three different things, in three different places

| | what it names | GCP (71 reports) | AWS shared tenancy (16 reports) |
|---|---|---|---|
| **VCEK / VLEK** — the endorsed signing key | VCEK: the chip (issued per `CHIP_ID` and TCB, served by AMD's KDS by `CHIP_ID`). VLEK: the cloud region (the certificate's `CSP_ID` extension reads `CN=cc-us-east-2.amazonaws.com`, `CN=cc-eu-west-1.amazonaws.com`) | VCEK, 71 of 71 | VLEK, 16 of 16; one key per region |
| **`CHIP_ID`** — *place* | the silicon | 6 distinct; **every chip served 2–3 instances over time** (14 instances on 6 chips) | **all-zero in 16 of 16** |
| **`REPORT_ID`** — *instance* | the guest | 14 distinct, one per instance | 8 distinct, one per instance |
| `FAMILY_ID`, `IMAGE_ID`, `HOST_DATA`, `MEASUREMENT` — *what is running* | the image and its configuration | 1, 1, 1, 2 distinct values | 1, 1, 1, 1 |

So: **no key is endorsed per instance on either cloud.** VCEK names the place, VLEK names the
class, and the only per-instance value — `REPORT_ID` — is a claim inside the signed body, not a
key. That is the measured answer to the granularity question endorsements-11 leaves open.

Two details a verifier has to know:

- **`CHIP_ID` is zero on AWS while the report's own `MASK_CHIP_KEY` flag is 0** in all 16
  reports. A verifier that consults the flag to decide whether `CHIP_ID` is meaningful is told it
  is, and then compares 64 zero bytes with 64 zero bytes. The reason lies in the platform's
  configuration, which the guest cannot see. The rule this repository uses is by content: an
  all-zero `CHIP_ID` is no place at all (`hatls/tee.py: snp_anchor`).
- **`REPORT_ID_MA` is all-ones in 87 of 87 reports**: no migration agent is configured in either
  deployment, so a `REPORT_ID` in this corpus cannot have travelled. Where a migration agent *is*
  configured, the firmware ABI's guest-context table marks `ReportID` as migrated with the guest
  — an instance identifier that follows the workload, by design — and the agent is then inside
  the trust boundary of that identity and must be appraised too.

## Why `REPORT_ID` is an instance identifier the hypervisor did not choose

The AMD SEV-SNP Firmware ABI (publication 56860) on the two fields:

> *"The firmware generates a report ID for each guest that persists with the guest instance
> throughout its lifetime. In each attestation report, the report ID is placed in REPORT_ID."*

> *`CHIP_ID`: "If MaskChipId is set to 0, Identifier unique to the chip. Otherwise, set to 0h."*

The guest-context table of the same specification lists `ReportID` as *"Generated using a
CSRNG"* and *"Migrated? Yes"* — a random value the firmware draws, kept with the guest if the
guest is migrated.

And the hypervisor's inputs to `SNP_LAUNCH_START`, from the Linux kernel's
`struct sev_data_snp_launch_start` (`include/linux/psp-sev.h`): `gctx_paddr`, `policy`,
`ma_gctx_paddr`, `ma_en`, `imi_en`, `desired_tsc_khz`, `gosvw`. `REPORT_ID` is not among them.
The value is the firmware's, made at launch, carried unchanged in every report of that guest.

## The IETF has written the ambiguity down — for a different question

draft-deeglaze-amd-sev-snp-corim-profile-02 says it plainly: *"The instance identifier can be
argued as any of REPORT_ID, REPORT_ID_MA when non-zero, CHIP_ID (for VCEK), or CSP_ID (for
VLEK)."* It then chooses: *"Given that REPORT_ID and REPORT_ID_MA are more ephemeral measured
values and not the instance of the AMD-SP as the attesting environment, they are relegated to
measurements."* — adding that endorsements specific to them *"SHOULD use a conditional
endorsement triple."*

That choice is right for the question the profile asks. In RATS terms it identifies the instance
of the **Attesting Environment**, and that is the AMD-SP: the chip. Continuity asks about the
instance of the **Target Environment**, the confidential VM whose key is to be kept honest. The
measurements above say `CHIP_ID` cannot answer that — every chip here hosted several guests — and
on shared tenancy it is not there at all. The gap is not that the profile is wrong; it is that a
verifier which reuses the attester's identity as the target's does so silently, and on a masked
platform reports a match between two strings of zeros.

## Intel TDX: no equivalent, and that is the finding

Two TDs launched from one image, a TDREPORT from each (`evidence/tdx-claims-20260921T211425Z/`),
every field of the 1024-byte structure compared at its offset: 16 fields identical — `MRTD`,
`RTMR0..3`, `MRCONFIGID`, `MROWNERCONFIG`, `SERVTD_HASH`, `ATTRIBUTES`, `XFAM`, `CPUSVN`,
`TEE_TCB_INFO` and its hash, `REPORTTYPE` — and three that differ: `TDINFO.MROWNER`, and through
it the TDINFO hash and the MAC.

Exactly one field separates two live TDs, and it is the wrong one. `MROWNER` is not produced by
the TDX module; the host VMM supplies it at TD initialisation (`KVM_TDX_INIT_VM`), and it defaults
to zero. A cloud writing something per-instance there is a convention that happens to be useful,
not a guarantee: the party that would re-host a workload is the party that picks the value. A
continuity design that works on SEV-SNP does not port to TDX by renaming a field; there the
instance identity has to come from outside the report.

## What this means for the three open questions

| question | on real silicon |
|---|---|
| endorsements-11 §4 — granularity of endorsed keys | per chip (VCEK) or per region (VLEK); **per instance: none** |
| use-cases 4.3 — a machine identifier | SEV-SNP: `REPORT_ID`, firmware-issued, not a launch input; but the silicon has no identity on AWS. TDX: only the host's `MROWNER` |
| use-cases 3.8.1 — continuity with an instance | possible on SEV-SNP by anchoring on `REPORT_ID`, which is what this repository does; **not possible from the TDREPORT alone** |

A note on wording: 4.3 asks for an identifier *"provided by the infrastructure provider"*.
`REPORT_ID` is provided by the firmware, not the provider, and no provider-supplied identifier
appears in any SEV-SNP report field measured here. Whether a firmware-issued instance identifier
satisfies the goal as the group means it is the group's question; this is what the chips give.
