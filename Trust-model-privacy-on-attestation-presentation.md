Trust Model: Privacy on credential presentation
===

**Version:** 1.0

# Chapter context
This chapter focuses on the requirements essential for the Verifiable Credentials (attestations) presentation process, outlining the associated risks and the mechanisms implemented to eliminate or mitigate these challenges.
In addition to the mechanisms for the presentation process, supplementary mechanisms must be developed for the Verifiable Credentials issuance process to safeguard citizens' full privacy and enhance the security of the framework. 
These additional mechanisms will be discussed in subsequent chapters.

# Table of Contents
- [1. Privacy and security challenges](#1-privacy-and-security-challenges)
  - [1.1. WSCDs and wallet binding](#11-wscds-and-wallet-binding)
    - [1.1.1. Implied revocation in case of WSCD compromise](#111-implied-revocation-in-case-of-wscd-compromise)
    - [1.1.2. Implied revocation in case of loss, theft... of the wallet](#112-implied-revocation-in-case-of-loss-theft-of-the-wallet)
  - [1.2. Attestation issuance](#12-attestation-issuance)
    - [1.2.1. Attestation identifier managed by the Issuer](#121-attestation-identifier-managed-by-the-issuer)
  - [1.3. Attestation presentation](#13-attestation-presentation)
    - [1.3.1. Holder tracking via holder's public elements and signatures by Verifiers](#131-holder-tracking-via-holders-public-elements-and-signatures-by-verifiers)
    - [1.3.2. Holder tracking via holder's public elements and signatures in case of Verifier and Issuer collusion](#132-holder-tracking-via-holders-public-elements-and-signatures-in-case-of-verifier-and-issuer-collusion)
    - [1.3.3. Holder tracking via digest values](#133-holder-tracking-via-digest-values)
    - [1.3.4. Holder tracking via salts used to calculate the digest](#134-holder-tracking-via-salts-used-to-calculate-the-digest)
    - [1.3.5. Everlasting privacy](#135-everlasting-privacy)
  - [1.4. Attestation revocation](#14-attestation-revocation)
    - [1.4.1 Holder tracking in case of collusion between Verifier and Issuer](#141-holder-tracking-in-case-of-collusion-between-verifier-and-issuer)
    - [1.4.2 Privacy preservation during revocation check on Issuer](#142-privacy-preservation-during-revocation-check-on-issuer)
- [2. Security and privacy mechanisms](#2-security-and-privacy-mechanisms)
  - [2.1 Static undisclosed digest](#21-static-undisclosed-digest)
  - [2.2 Digest calculation without salt](#22-digest-calculation-without-salt)
  - [2.3 Attestation identifier computation](#23-attestation-identifier-computation)
  - [2.4 Holder Public key and Issuer signature randomization during the presentation process](#24-holder-public-key-and-issuer-signature-randomization-during-the-presentation-process)
    - [2.4.1 Holder Public key randomization during the presentation process](#241-holder-public-key-randomization-during-the-presentation-process)
    - [2.4.2 Issuer signature randomization during the presentation process](#242-issuer-signature-randomization-during-the-presentation-process)
    - [2.4.3 End to End high level flow](#243-end-to-end-high-level-flow)
  - [2.5 Proofs with accumulators](#25-proofs-with-accumulators)
    - [2.5.1 Non-expiration proof with accumulators](#251-non-expiration-proof-with-accumulators)
    - [2.5.2 Non-revocation proof with accumulators](#252-non-revocation-proof-with-accumulators)
  - [2.6 Wallet instance identifier and WSCD references in attestations](#26-wallet-instance-identifier-and-wscd-references-in-attestations)
    - [Protection against Wallet loss or theft.](#protection-against-wallet-loss-or-theft)
    - [Protection against WSCD breach](#protection-against-wscd-breach)
    - [2.6.1 Wallet and WSCDs references in attestations during issuance process](#261-wallet-and-wscds-references-in-attestations-during-issuance-process)
    - [2.6.2 Wallet and WSCDs references in attestations during presentation process](#262-wallet-and-wscds-references-in-attestations-during-presentation-process)
- [3. Coverage of security and privacy challenges by the mechanisms](#3-coverage-of-security-and-privacy-challenges-by-the-mechanisms)
- [4. BBS# implementation in SSI flows](#4-bbs-implementation-in-ssi-flows)
  - [4.1 Validation of transaction when not using pairing](#41-validation-of-transaction-when-not-using-pairing)
    - [4.1.1 Holder requests a signature validity proofs on each presentation](#411-holder-requests-a-signature-validity-proofs-on-each-presentation)
    - [4.1.2 Verifier obtain the signature validity proofs from the Issuer](#412-verifier-obtain-the-signature-validity-proofs-from-the-issuer)
    - [4.1.3 Holder stores batches of signature validity proofs](#413-holder-stores-batches-of-signature-validity-proofs)
    - [4.1.4 DDoS protection of Issuer's proof of validity APIs](#414-ddos-protection-of-issuers-proof-of-validity-apis)
  - [4.2 Attestation issuance flow](#42-attestation-issuance-flow)
  - [4.3 Attestation presentation flow](#43-attestation-presentation-flow)
  - [4.4 Description of proofs during presentation](#44-description-of-proofs-during-presentation)
    - [4.4.1 Description of the attestation signature](#441-description-of-the-attestation-signature)
    - [4.4.1 Description of the presentation signature](#441-description-of-the-presentation-signature)


# 1. Privacy and security challenges
In the context of the European Digital Identity Wallet, privacy and security are paramount concerns that must be addressed to ensure user trust and compliance with regulatory frameworks such as GDPR. This section aims to provide a comprehensive overview of the privacy and security risks, setting the stage for subsequent discussions on proposed mechanisms to mitigate these challenges effectively.


## 1.1. WSCDs and wallet binding

### 1.1.1. Implied revocation in case of WSCD compromise
In the event of a WSCD compromise, all attestations issued and bound to a Holder public key managed by the WSCD must be invalidated. 
The process of revoking these attestations necessitates notifying all Issuers, who must then implement the attestation revocation based on the WSCD identifier. 
This workflow involves multiple actors and requires validation of the Issuer's implementation. 

Therefore, this approach is not considered robust.

### 1.1.2. Implied revocation in case of loss, theft... of the wallet 
In this case, the Wallet instance is compromised. 
In the event of a Wallet instance compromise, all attestations issued and bound to a Holder public key managed by the Wallet instance must be invalidated.
The process of revoking these attestations necessitates notifying all Issuers, who must then implement the attestation revocation based on the Wallet instance identifier.
This workflow involves multiple actors and requires validation of the Issuer's implementation.

Therefore, this approach is not considered robust.


## 1.2. Attestation issuance

### 1.2.1. Attestation identifier managed by the Issuer
The attestation identifier is required to manage the attestation revocation.
If the Issuer is the only entity to forge the attestation identifier, a malicious Issuer could forge an identifier that allows the tracking of the Holder (Holder is part of a group, for instance).

Additionally, this could impact applications such as petitions/polls/online-voting, as it could prevent certain people from voting or signing petitions: a malicious Issuer could add the attestation identifier to a black list, for instance.


## 1.3. Attestation presentation

### 1.3.1. Holder tracking via holder's public elements and signatures by Verifiers
During the presentation process, the wallet transmits traceable attestation elements to the verifier, such as:
- Holder public key
- Issuer signature
- WSCD, wallet instance identifiers

These elements are sealed by the Issuer's signature and therefore do not vary between different presentations. 
Based on these elements, a Verifier or colluding malicious Verifiers can track the holder.

For example, 
a Verifier can track the attestation's digital signature to detect multiple presentations by the same holder,
even though the attributes of the presentation do not disclose any identifying claims about the holder.

### 1.3.2. Holder tracking via holder's public elements and signatures in case of Verifier and Issuer collusion
During the issuance and presentation process, some common elements are known by both the Issuer and verifier, such as:
- Holder public key
- Issuer signature (produced by the issuer)
- WSCD, wallet instance identifiers

Shared elements between Issuers and Verifiers create a vulnerability: colluding malicious entities (Issuers and Verifiers) 
can exploit this commonality to track Holders across the system.

For example,  
a Verifier, upon receiving an anonymized attestation, 
can potentially deanonymize the Holder by leveraging the attestation's signature to query the Issuer for the holder's identity.

### 1.3.3. Holder tracking via digest values
In the context of selective disclosure, claims are encoded with a digest in SD-JWT and MSO formats. 
During the presentation process, even if a claim is not disclosed, the digest is included in the attestation, 
allowing Verifiers to track the Holder based on the digest value, which does not vary across multiple presentations.
This allows the Verifier to conclude that both presentations originate from the same Holder and can combine these pieces of information to extend the Holder's profile with each later presentation.

Therefore, the use of digests poses significant privacy risks:
- **Tracking by malicious Verifier:** A malicious Verifier can track the Holder across different presentations by correlating the digests.
- **Malicious Colluded Verifiers:** Multiple Verifiers working together can share and correlate digests to track the Holder.
- **Malicious Colluded Issuer-Verifier:** An Issuer and Verifier working together can share and correlate digests to track the Holder.

### 1.3.4. Holder tracking via salts used to calculate the digest
In the context of selective disclosure, salts are used to encode plaintext claims into digests. 
Each claim must be salted independently with a unique salt. 
However, during the presentation process, a Verifier can track the salts of disclosed claims to profile and track the Holder.

For example, if a Holder presents the same attestation to the Verifier twice, with the same disclosure, the salt will be identical, allowing the Verifier to use this information to track the holder.

Another example with Verifier collusion:
- **First Presentation on verifierA requested a proof of age:** The Holder uses their identity attestation and only discloses their age of a majority.
- **Second Presentation on verifierB requested the user identity:** The Holder uses their identity attestation and discloses all attestation claims.

The Verifiers can track the Holder by identifying the salt associated with the age of a majority in both presentations. 
This allows both Verifiers to conclude that both presentations originate from the same Holder and to combine their information about the Holder activity.

The use of salts to compute the digest, poses significant privacy risks:
- **Tracking by malicious Verifier:** A malicious Verifier can track the Holder across different presentations by correlating the salts.
- **Malicious colluded Verifiers:** Multiple Verifiers working together can share and correlate salts to track the Holder.
- **Malicious colluded Issuer-Verifier:** An Issuer and Verifier working together can share and correlate salts to track the Holder.

### 1.3.5. Everlasting privacy
With the advent of quantum computing, attackers will potentially be able to break most of the current asymmetric cryptographic standards. 
This introduces the risk of "steal now, decrypt later" (retrospective decryption). 
Data intercepted and stored today could be decrypted in the future when quantum computing becomes more advanced, exposing the Holder's privacy.
Sensitive use cases like petitions, polls, and online voting are particularly vulnerable, as the Holder's identity could be revealed long after the data was initially captured.


## 1.4. Attestation revocation
Several solutions are proposed to provide the Verifier with proof of non-revocation of an attestation, such as certificate revocation lists or proof based on tokens issued by the Issuer. 
However, all these solutions involve one of the following risks:

### 1.4.1 Holder tracking in case of collusion between Verifier and Issuer
In solutions where the Issuer interacts during verification, a potential security vulnerability arises if the Issuer colludes with the Verifier. 
This collusion enables timing correlation attacks, allowing the tracing of a holder's activities based on transaction timestamps. 

A potential privacy vulnerability exists when the Holder fetches a non-revocation proof from the Issuer prior to Verifier presentation. 
If the Issuer and Verifier collude, they can correlate their respective timestamps and metadata to deanonymize the holder. 

### 1.4.2 Privacy preservation during revocation check on Issuer
In scenarios where the Verifier must validate attestation status with the Issuer, it enables the Issuer to collect information about the attestation presentation. 
This includes attestation type, Holder identity, Verifier identity, and timestamp of the verification request...

For example, 
when a Verifier queries an Issuer's revocation registry to check an attestation's status, 
The Issuer can infer the holder's attestation usage from these queries. 



# 2. Security and privacy mechanisms
This section outlines implementable mechanisms to mitigate the aforementioned privacy and security challenges.
These solutions are derived in part from the BBS#<sup>[[02](./Trust-model-Introduction.md#references)]</sup>.

## 2.1 Static undisclosed digest
This mechanism is designed to mitigate the risk of Holder tracking through the use of digest values by substituting the original digest value. This approach not only enhances user privacy but also ensures interoperability with existing standards.

The mechanism implements a local wallet process during the anonymization step of attestation presentation to replace the potentially trackable digest with a commitment to the digest. Since the digest cannot be replaced by a commitment without impacting the attestation format (for instance, 256 characters in the SD-JWT format), the digest is replaced with a static value, and the commitment is included with the attestation issuer's signature. This static value should be defined by convention, for example, as "0000000000000000000000000000000000000000000," to ensure compatibility with attestation format standards. A global static value helps mitigate risks associated with timing attacks if the Holder must contact a third party to retrieve it.

The process maintains attestation integrity through the following steps (This process is carried out at each presentation):
- **Digest Commitment**: The wallet computes a cryptographic commitment of the original digest.
- **Zero-Knowledge Proof (ZKP) Generation**: The wallet generates a ZKP to demonstrate that the issuer's signature is valid for all the attestation data, including the undisclosed data replaced by commitments.
- **Signature Augmentation**: The commitment and the ZKP are added to the issuer's signature.

This mechanism aims to prevent the risk of [Holder tracking via digest values](#133-holder-tracking-via-digest-values) by substituting the digest value. 
In addition, this solution aligns with the mechanisms for selective disclosure as defined in the ISO mDL and SD-JWT formats, 
ensuring that it can be integrated into existing systems without disruption.
This approach enhances privacy while maintaining interoperability with existing standards.

Below is a non-normative example of a SD-JWT attestation, presented to a Verifier with two undisclosed values:
```
- Payload:
{
  "_sd": [
    "mqXw1Euo3ut4y7cVBrTNbFuhv8O0VSXahlD5twVdLD8",
    "0000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000"
  ],
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "type": "https://credentials.example.com/VC_example",
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {...}
  }
}
- Signature:
<issuerSignature>+<CommitmentOfUndisclosedClaims>+<ZkpForUndisclosedClaims>
- Disclosure:
WyJGR2YwQ09LQnFsenU5SlF0cDhiRGFBPT0iLCJsYXN0TmFtZSIsIkRvZSJd
```

Another property of this mechanism is the preservation of [everlasting privacy](#135-everlasting-privacy) through the use of commitments. 
By embedding undisclosed values within commitments (and using static values in the attestation to maintain format compatibility), 
we ensure that these attributes will never be revealed in the future.

## 2.2 Digest calculation without salt
The goal of this directive is to remove the salt for the digest computation, which can be used as a means to track the Holder [via salts used to calculate the digest](#134-holder-tracking-via-salts-used-to-calculate-the-digest).

The randomness in the digest computation ensures that the same plaintext claim value does not produce the same digest value. It also makes it infeasible to guess the preimage of the digest (and thereby learn the plaintext claim value) by enumerating potential values for a claim in the hash function to search for a matching digest value.

Therefore, to ensure Holder privacy, the digests of undisclosed claims shall not be revealed during the presentation process (cf. section [Static undisclosed digest](#21-static-undisclosed-digest)). Thus, there is no security requirement to add salt in the digest computation.

> Note: This directive requires making salt optional for the calculation of the digest in the specifications of the attestation formats discussed in this document.


## 2.3 Attestation identifier computation
The attestation identifier is required for the attestation non-revocation proof process (cf. section [non revocation proof with accumulators](#252-non-revocation-proof-with-accumulators)).
To address the risk described in section [attestation identifier managed by the issuer](#121-attestation-identifier-managed-by-the-issuer), we propose defining a convention for computing the attestation identifier:
- The attestation identifier must be generated by applying a one-way function to the holder's public key.

This solution has several advantages:
- **Guaranteed uniqueness**: Since the holder's public key must be unique for each transaction to ensure privacy, the identifier based on it will also be unique.
- **No additional exchanges required**: It does not require additional exchanges between the Holder and the issuer.
- **Verification of compliance**: The Holder can verify at the end of the issuance process that the Issuer has adhered to the convention.
- **Confidentiality**: The identifier is known only to the Issuer and the holder, ensuring no one else has access to it.


## 2.4 Holder Public key and Issuer signature randomization during the presentation process
The goal of these mechanisms is to prevent Holder tracking based on their public key and signatures.
The randomization of the Holder's public key and Issuer's signature mitigates the risk of:
- [Holder tracking via holder's public elements and signatures by Verifiers](#131-holder-tracking-via-holders-public-elements-and-signatures-by-verifiers) during the attestation presentation process.
- [Holder tracking via holder's public elements and signatures in case of Verifier and Issuer collusion](#132-holder-tracking-via-holders-public-elements-and-signatures-in-case-of-verifier-and-issuer-collusion) during the attestation presentation process.

### 2.4.1 Holder Public key randomization during the presentation process

Most WSCDs support common digital signature algorithms, such as ECDSA.
However, developers are restricted from implementing new cryptographic functionalities for security reasons.
This limitation makes it challenging to use these WSCDs for purposes beyond their original design, such as generating blinded public keys (blind_pk<sub>Holder</sub>). 
Consequently, a WSCD cannot perform operations like "blinding" its own public key,
nor can a WSCD generate the signature (blind_signature<sub>Holder</sub>) associated with blind_pk<sub>Holder</sub>.

**Randomization Process**
The following outlines how a WSCD and the associated Wallet application can collaboratively anonymize the public key (blind_pk<sub>Holder</sub>) 
and compute the anonymized signature (blind_signature<sub>Holder</sub>).
We propose two variants of BBS#: in the first one, we assume that the digital signature algorithm supported by the WSCD is EC-SDSA (ECSchnorr),
while in the second one, we assume it is ECDSA.

**Variant 1: EC-SDSA (Elliptic Curve Schnorr Digital Signature Algorithm)**

In this variant, we assume that the digital signature algorithm supported by the WSCD is EC-SDSA. 
The Wallet application can leverage the capabilities of EC-SDSA to facilitate the randomization process and generate the corresponding randomization signature.

Joint computation of blind_pk<sub>Holder</sub> and blind_signature<sub>Holder</sub> with EC-SDSA (ECSchnorr):

![Joint computation of blind_pk<sub>Holder</sub> and blind_signature<sub>Holder</sub> with EC-SDSA (ECSchnorr)](./media/1/key-anonymization-ecschnorr.png)

**Variant 2: ECDSA (Elliptic Curve Digital Signature Algorithm)**

Below, we explain how the WSCD and the associated Wallet application can jointly randomization the public key blind_pk<sub>Holder</sub> 
and calculate the anonymized blind_signature<sub>Holder</sub>.

Joint computation of blind_pk<sub>Holder</sub> and blind_signature<sub>Holder</sub> with EC-SDSA (ECSchnorr):

![Joint computation of blind_pk<sub>Holder</sub> and blind_signature<sub>Holder</sub> with EC-SDSA (ECSchnorr)](./media/1/key-anonymization-ecdsa.png)


**Note:**
**In the remainder of this document, 
the discussion and examples will be presented using EC-SDSA as the signature algorithm. 
However, as previously indicated, the reasoning and principles outlined can also be applied to ECDSA.**


### 2.4.2 Issuer signature randomization during the presentation process
Using the properties of BBS+, 
the Wallet can randomize the BBS+ signature of the Verifiable Credential issued by the Issuer. 
This process enables the computation of the blinded Issuer signature (blind_signature<sub>Issuer</sub>), 
effectively preventing both the Issuer and the Verifier 
from tracking the Holder through the Issuer's signature footprint.

### 2.4.3 End to End high level flow

The following sequence outlines the process of anonymizing the Holder's public key, 
Holder's signature, and Issuer's signature during the presentation of an attestation. 
For the sake of simplicity, we will focus on the presentation of a single attestation.

Assumptions:
* Each Holder manages a unique EC-SDSA key pair, which is used for cryptographic binding to the Holder.
* The private key associated with this key pair is generated and exclusively controlled by the Holder's WSCD.

![Randomization during the presentation process - EC-SDSA](./media/1/blind-holder-ecsdsa-presentation.png)

**Flow description**
- [01]: This step represents the initial step of the presentation process, which are not detailed in this context.
- [02]: The Wallet generates a new random value (**r<sub>holder</sub>**) locally. This random is used exclusively for the Presentation transaction, meaning it does not need to be stored or generated thanks to the capabilities of a WCSD.
- [03]: At this step, we have generated a new Holder public key (**pk_blind<sub>holder</sub>**) that is designed to be unrecognizable by the credential Issuer, as well as by any other Issuers and Verifiers with whom the Holder has previously interacted.
- [04-05]: The Wallet generates a new random value (**r<sub>issuer</sub>**) to refresh the Issuer's signature. This random is used exclusively for the Presentation transaction, meaning it does not need to be stored or generated thanks to the capabilities of a WCSD. At this step, we have a refreshed attestation bound to **pk_blind<sub>holder</sub>**, signed with **signature_blind<sub>issuer</sub>**. 
- [06]: The wallet generates a zero-knowledge proof (ZKP) called **attestation_integrity_ZKP** to prove the integrity of the refreshed attestation to the Issuer. The functional description of this proof is as follows: 
  - The Holder knows a public key (**pk<sub>holder</sub>**) and a random value (**r<sub>holder</sub>**) such that applying **r<sub>holder</sub>** to **pk<sub>holder</sub>** results in **pk_blind<sub>holder</sub>**
  - The Holder knows a signature (**signature<sub>issuer</sub>**) and a random value (**r<sub>issuer</sub>**) such that applying **r<sub>issuer</sub>** to **signature<sub>issuer</sub>** results in **signature_blind<sub>issuer</sub>**
  - The blinded Issuer signature **signature_blind<sub>issuer</sub>** relates to the attestation data, which includes the blinded Holder public key **pk_blind<sub>holder</sub>**
- [08-10]: The Wallet crafts the presentation for the Verifier and signs it using their WSCD. The **signature<sub>holder</sub>** is an ECSDSA signature on the **Presentation** that can be verified with **pk<sub>holder</sub>**.
- [11]: The Wallet anonymizes the signature to get a signature that can be verified with the blinded Holder's public key, previously generated. The **signature_blind<sub>holder</sub>** is an ECSDSA signature on the **Presentation** that can be verified with **pk_blind<sub>holder</sub>**.
- [12]: The wallet generates a zero-knowledge proof (ZKP) called **key_binding_ZKP** to prove that the Holder knows a  **sk_blind<sub>holder</sub>** associated to **pk_blind<sub>holder</sub>**.
- [13]: The Wallet sends the presentation to the Verifier, who can verify it.

This flow is executed for each presentation,
allowing the Holder to share a new public key value and a refreshed attestation for every transaction.
Consequently, the Holder public key and the Holder signature presented to the Verifier will consistently vary.


## 2.5 Proofs with accumulators
This section outlines how the accumulators facilitate the proof to the Verifier that the presented attestation has not been revoked,
while canceling the risk of [Holder tracking during the revocation process in scenarios where there may be collusion between the Verifier and Issuer](#141-linkability-in-case-of-collusion-between-verifier-and-issuer), 
as well as the risk of [Holder usage deduction by the Issuer during the Verifier's revocation check](#142-privacy-preservation-during-revocation-check-on-issuer).

An accumulator is a fixed-size structure (usually 256 bits) that allows adding or removing values and proving via Zero-Knowledge Proof (ZKP) whether a specific value is included or not, with the capacity to hold billions of values. 

To build this type of Zero-Knowledge Proof (ZKP), two elements are required:
- **The Witness**: Provided by the Issuer during the attestation issuance process. The witness must be updated in sync with the accumulator value whenever a serial number is added to or removed from the accumulator.
- **The Accumulator State**: This state must be synchronized between the Prover and the Verifier. The accumulator value changes when a value is added or removed. Therefore, to calculate and verify the Zero-Knowledge Proof (ZKP), both parties must work with the same accumulator state.

The Zero-Knowledge Proof (ZKP) computed by the Wallet is not directly verifiable by the Verifier, 
as we use **non-pairing curve accumulators** to enhance certifiability. 
The Verifier must forward the ZKP to the owner of the accumulator, who possesses the ability to verify the proof.
Upon successful verification, the accumulator owner returns a Proof of Validity (PoV) for the ZKP, confirming its authenticity.

Both the ZKP and the PoV are designed to be completely anonymous, 
ensuring that no information about the Holder is disclosed during the verification process.
This approach maintains the confidentiality of the Holder's identity and associated data, 
reinforcing the privacy-preserving features of the system.

In addition to ensuring privacy, this solution also provides the following advantages:
- **Mitigates timing attacks**: No information is transmitted that could correlate interactions among different actors in the EUDI Wallet Framework.
- **Wallet offline compatibility**: Since the accumulator state is sent by the Verifier to the Holder, the Wallet can operate offline.

This solution can be used to demonstrate both attestation non-expiration and non-revocation, as outlined below.

### 2.5.1 Non-expiration proof with accumulators
This mechanism enables the Holder to demonstrate to the Verifier 
that the shared attestation is not expired without disclosing the attestation's issuance date. 
This mechanism is crucial for maintaining Holder privacy while allowing the Verifier to confirm that the shared attestation is not expired.

The non-expiration proof utilizes an accumulator that maintains a record of all expired dates, which is updated daily with the previous day's date.
The non-expiration proof mechanism leverages a daily-updated accumulator of expired dates, combined with ZKP, 
to ensure that the attestation date remains confidential while proving its validity. 
We recommend to limit expiration date precision to one day. 
This accumulator can be shared among all actors because its content is predictable.

The following sequence diagram illustrates how to compute and verify the attestation non-expiration proof :

![Non-expiration proof with accumulators](./media/1/accumulator-expiration.png)

**Flow description**
- [01]: This step represents the initial step of the presentation process, which is not detailed in this context.
- [02]: The Wallet retrieves the witness and the accumulator state related to the expiration date, previously stored beside the attestation.
- [03]: The Wallet updates the witness using the up to date expiredDate accumulator state. This state can be retrieved once a day. If the Holder is offline, the witness can be updated without interaction with the Registry, as its content is predictable.
- [04]: The Wallet generates a non-expiration Zero-Knowledge Proof (ZKP) based on the witness.
- [05]: The Wallet sends the presentation to the Verifier, including the shared attestation and the non-expiration ZKP.
- [06]: The Verifier is unable to directly check the proof on its own due to the utilization of non-pairing curve accumulators. The Verifier shall contact the Registry to obtain a proof of validity (PoV).
- [07-08]: The registry checks the validity of the non-expiration ZKP and generates a PoV for the non-expiration ZKP. If the non-expiration ZKP is based on an outdated version of the expiredDate accumulator, the verification will fail, indicating that the attestation may no longer be valid. Upon successful verification, the Registry returns the PoV to the Verifier.
- [09]: The Verifier can confirm that the attestation is not expired without needing to know the attestation issuance date.

### 2.5.2 Non-revocation proof with accumulators

This mechanism enables the proof to the Verifier that the shared attestation is not revoked without revealing the attestation identifier.
This design choice is essential for protecting Holder privacy and preventing any potential tracking based on the attestation identifier.

We propose that accumulators be managed by the Issuers and that attestations include an identifier 
(generated using the method described in the section on [attestation identifier computation](#25-attestation-identifier-computation)).
This identifier can be added to the accumulators based on the revocation list approach, which can either be an allowlist or a blacklist.

To prevent privacy issues, the attestation identifier shall not be disclosed to the Verifier. 
Therefore, during the presentation, the Holder sends a proof in the form of a Zero-Knowledge Proof (ZKP) to the Verifier, 
demonstrating that the attestation identifier is not included in the accumulator (in the case of a blacklist).

The witness corresponding to the attestation identifier is provided by the Issuer during the issuance process, along with the corresponding accumulator state. This pair is stored on the Wallet side alongside the attestation and is used during the attestation presentation process.

The following sequence diagram illustrates how the attestation non-revocation proof is computed and verified:

![Non-revocation proof with accumulators](./media/1/accumulator-revocation.png)

**Flow description**
- [01]: This step represents the initial phase of the presentation process, which is not detailed in this context.
- [02]: The wallet retrieves the witness and the accumulator state associated with the attestation's revocation status, which is stored alongside the attestation. If the accumulator state is recent, the subsequent steps to obtain an updated state may not be necessary. In some use cases depending on Verifier requirements, the proof that the verifiable credential was not revoked a few days prior may be deemed acceptable. Alternatively, the wallet can synchronize the accumulator states independently of the transaction (e.g., through a background process). 
These two options neutralize the risk of the Issuer (the revocation registry owner) correlating the accumulator state value with the synchronization request and the proof verification request.
Such correlations could potentially enable the Issuer to track the Holder's usage, particularly in scenarios characterized by very low traffic and usage.
- [03-04]: If the Wallet is online, it can contact the Issuer of the attestation to retrieve the necessary information to update its accumulator state and witness. The Issuer computes the delta, which represents the updates between the Wallet's accumulator state and the Issuer's current accumulator value, and sends this delta to the Wallet. 
Using the delta helps limit the data overhead during the exchange.
- [05-08]: If the Wallet is offline, it can obtain the accumulator state and delta through the verifier. In this scenario, it is crucial that the Issuer's response is signed to ensure that the Wallet can verify the integrity of the data and confirm that the Verifier has not altered it.
- [09-10]: The Wallet updates its accumulator state and the corresponding witness for the attestation using the retrieved delta.
- [11]: The Wallet generates a non-revocation Zero-Knowledge Proof (ZKP) based on the witness.
- [12]: The Wallet sends the presentation to the Verifier, including the shared attestation and the non-revocation ZKP.
- [13]: The Verifier is unable to directly check the proof on its own due to the utilization of non-pairing curve accumulators. The Verifier shall contact the Registry to obtain a proof of validity (PoV).
- [14-15]: The registry checks the validity of the non-revocation ZKP and generates a PoV for the non-revocation ZKP. 
If the non-revocation ZKP is based on an outdated version of the accumulator, the verification will fail.
Upon successful verification, the Issuer returns the PoV to the Verifier.
- [16]: The Verifier can confirm that the attestation is not revoked without needing to know the attestation identifier or any other references of the attestation which could be tracked.

**Note: potential improvement**

To optimize the number of interactions between the parties, 
the Holder and the Verifier may agree to utilize an older version (rather than the most recent) of an accumulator. 
The acceptable time window for this agreement, based on the Verifier's requirements, can be defined in the Presentation Definition.
By allowing the use of an older accumulator version, the Wallet can avoid the need to synchronize the accumulator state with each transaction, 
thereby minimizing the number of interactions required between the Holder and the Verifier.

## 2.6 Wallet instance identifier and WSCD references in attestations

The goal of this directive is to include the WSCD reference and Wallet-Instance identifier reference in all issued attestations.
This inclusion is essential for enabling:
* [Implied revocation in case of WSCD compromise](#111-implied-revocation-in-case-of-wscds-compromise) 
* [Implied revocation in case of loss or theft of the Wallet](#112-implied-revocation-in-case-of-loss-theft-of-the-wallet).


The WSCD reference and the Wallet-Instance identifier can be retrieved from the Wallet Attestation 
issued by the Wallet Provider during the onboarding process. 
In addition to attesting to the authenticity of the Wallet-Instance, 
the Wallet Attestation provides the following assurances:

- **Protection of Private Key:** The Wallet Attestation certifies that the Holder's private key is safeguarded by a certified WSCD, identified by its reference,
which possesses the required properties and security posture.

- **Key binding:** The attestation is explicitly bound to the Holder's public key, ensuring that the credentials are linked to the correct identity.

- **Identifier binding:** The Wallet Attestation is associated with a specific identifier

- **User Account link**: The Wallet Attestation is linked to the Holder's user account within the Wallet provider's System of Identity (SI)

The Wallet Attestation, similar to any other attestation, leverages BBS# mechanisms to provide anonymization features during interactions with other parties, such as Issuers and Verifiers.

**Note:**
Wallet Attestation anonymization during the issuance process is not described in this document.

Including the WSCD reference and the Wallet-Instance identifier in all issued attestations facilitates implied revocation features:

### Protection against Wallet loss or theft
During the presentation process, 
the Verifier must ensure that the Wallet-Instance identifier referenced in the attestation is not revoked by the Wallet Provider.
Actually for privacy compliance, the Holder shall provide a proof (ZKP) demonstrating that the Wallet-Instance is not revoked.
The user can revoke all their attestations by contacting the Wallet provider.
If the Wallet provider revokes the **Wallet Attestation** associated with the Holder's user account, 
this action will automatically lead to the revocation of all linked attestations. 
This cascading effect ensures that any attestations tied to the compromised Wallet-Instance are immediately rendered invalid.


### Protection against WSCD breach
During the presentation process,
the Verifier must ensure that the WSCD referenced in the attestation is not revoked by the WSCD Provider (or an authority).
Actually for privacy compliance, the Holder shall provide a proof (ZKP) demonstrating that the WSCD is not revoked.
If a WSCD is compromised, its reference will be added to a list of revoked WSCDs, 
and consequently, no attestation linked to that WSCD will be accepted.


This mechanism enables immediate cascading revocation without the need for intermediaries. 
Involving intermediaries in the revocation process could introduce security issues, 
particularly if one of them fails to implement the revocation procedures correctly.

Involving intermediaries in the revocation process can introduce potential security vulnerabilities, 
particularly if any intermediary fails to implement the revocation procedures correctly.
By avoiding intermediary, the system enhances reliability and trust in the revocation management.


### 2.6.1 Wallet and WSCDs references in attestations during issuance process
During the wallet attestation presentation, the identifier of the WSCD and the wallet attestation identifier are transmitted to the issuer. The Issuer must then incorporate these values into the attestation to bind it with the WSCD and the wallet attestation.

The following sequence diagram details this process:

![Wallet and WSCDs references in attestations - issuance](./media/1/wallet-attestation-references-issuance.png)

**Flow description**
- [01]: Before being able to collect an attestation, the wallet must retrieve (during the onboarding process) a wallet attestation issued by the wallet provider. This wallet attestation is bound to the wallet instance and the WSCD that stores the holder's private key.
- [02]: Later, during the attestation issuance process, the wallet generates a presentation of its wallet attestation. This presentation must be signed with the same Holder key as the holder's key pair bound to the wallet attestation.
- [03]: The wallet initiates the authorization code flow (PAR), and the Issuer authenticates the client based on the shared presentation of the wallet attestation. The Issuer checks that the wallet attestation is not revoked or expired, and that the WSCD referenced in the attestation is not compromised. At the end of the flow, the wallet retrieves an access token.
- [04-05]: The wallet generates a proof of possession of the holder's key pair. This proof must be signed with the same Holder key as the holder's key pair bound to the wallet attestation. The wallet then calls the Issuer to retrieve the attestation.
- [06]: The Issuer checks that the sent proof of possession of the holder's key pair is valid and that it references the same key as the key referenced in the shared wallet attestation. This step is necessary to ensure that the issued attestation will be bound to a key pair managed by a valid WSCD.
- [07-08]: The Issuer generates the attestation, adding the wallet attestation ID and WSCD reference to it, and sends it to the wallet.

### 2.6.2 Wallet and WSCDs references in attestations during presentation process
At the end of the attestation issuance process, the Holder obtains an attestation referencing the wallet attestation ID and the WSCD used to store the holder's secret. During the presentation of this attestation, the wallet must not disclose these claims that could be used to track the holder. 

Therefore, the wallet must prove to the Issuer that the wallet attestation referenced in the attestation, but not disclosed to the verifier, is not revoked or expired, and that the WSCD is not compromised. The following sequence diagram illustrates how the wallet provides these zero-knowledge proofs (ZKP) to the Verifier during the presentation of an attestation:

![Wallet and WSCDs references in attestations - presentation](./media/1/wallet-attestation-references-presentation.png)

**Flow description**
- [01]: This step represents the initial phase of the presentation process, which is not detailed in this context.
- [02-04]: The wallet synchronizes its accumulator states to generate proofs based on these accumulators. The detailed process for this step is described in the section [non revocation proof with accumulators](#252-non-revocation-proof-with-accumulators).
- [05-07]: The wallet generates the non-revocation Zero-Knowledge Proofs (ZKP) for both the wallet attestation and the WSCD references. The attestation is refreshed to anonymize he walletAttestationID and the WSCD reference, replacing them with static values. The detailed process is outlined in the section [static undisclosed digest](#21-static-undisclosed-digest). The generated proofs are added to the attestation signature according to a specified format. To simplify the flow, the holder's public key and the attestation issuer's signature are not obfuscated in this sequence; however, this step is mandatory to prevent Holder tracking.
- [8-9]: The wallet constructs the presentation, including the refreshed attestation, and sends it to the verifier. As before, to simplify the flow, the holder's signature is not randomized, but this step is essential to prevent Holder tracking. For more details about this process, see the section [Holder Public key and Issuer signature randomization during the presentation process](#24-holder-public-key-and-issuer-signature-randomization-during-the-presentation-process).
- [10-12]: The Verifier checks the validity of the attestation: To verify the non-revocation ZKP for both the attestation and the WSCD, the Verifier must contact the corresponding registry, as the accumulators are pairing-free. For more information, refer to the section [proofs with accumulators](#25-proofs-with-accumulators).



# 3. Coverage of security and privacy challenges by the mechanisms
This chapter aims at providing a comprehensive overview of how the proposed mechanisms address the identified security and privacy risks. This chapter presents a matrix that aligns the risks identified in Chapter 2 with the corresponding mechanisms that resolve or mitigate them. The matrix highlights which risks are covered (:white_check_mark:) by the proposed mechanisms.

By mapping the risks to the corresponding mechanisms, this chapter offers a clear understanding of how the proposed solutions address the security and privacy challenges outlined in the previous chapter. This matrix serves as a valuable reference for evaluating the effectiveness of the proposed mechanisms.

| Risks \ Mechanims|[Static UD. digest](#21-static-undisclosed-digest) |[Digest salt](#22-digest-calculation-without-salt) |[Id calculation](#23-attestation-identifier-computation) |[Randomization during presentation](#24-holder-public-key-and-issuer-signature-randomization-during-the-presentation-process) |[Non exp. proof](#251-non-expiration-proof-with-accumulators) |[Non revoc. proof](#252-non-revocation-proof-with-accumulators) |[Wallet & Wscd reference](#26-wallet-and-wscds-references-in-attestations) |
|-------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| [Implied revocation (WSCDs)](#111-implied-revocation-in-case-of-wscds-compromise)                                                                   | | | | | | |:white_check_mark:|
| [Implied revocation (wallet)](#112-implied-revocation-in-case-of-loss-theft-of-the-wallet)                                                          | | | | | | |:white_check_mark:|
| [Attestation identifier](#121-attestation-identifier-managed-by-the-issuer)                                                                         | | |:white_check_mark:| | | | |
| [Presentation: linkability by Verifiers](#131-holder-tracking-via-holders-public-elements-and-signatures-by-verifiers)                             | | | |:white_check_mark:|:white_check_mark:| | |
| [Presentation: linkability via collusion](#132-holder-tracking-via-holders-public-elements-and-signatures-in-case-of-verifier-and-issuer-collusion)| | | |:white_check_mark:| | | |
| [Linkability via digest values](#133-holder-tracking-via-digest-values)                                                                             |:white_check_mark:| | | | | | |
| [Linkability via digest salt](#134-holder-tracking-via-salts-used-to-calculate-the-digest)                                                          | |:white_check_mark:| | | | | |
| [Everlasting privacy](#135-everlasting-privacy)                                                                                                     | |:white_check_mark:| | | | | |
| [Revocation: linkability via collusion](#141-holder-tracking-in-case-of-collusion-between-verifier-and-issuer)                                     | | | | | |:white_check_mark:| |
| [Linkability during revocation check](#142-privacy-preservation-during-revocation-check-on-issuer)                                                  | | | | | |:white_check_mark:| |



# 4. BBS# implementation in SSI flows
This chapter focuses on the implementation of the BBS# protocol within Self-Sovereign Identity (SSI) flows during the attestation issuance and presentation, by detailing how the previously discussed mechanisms interact and function together to enhances the privacy and security.


## 4.1 Validation of transaction when not using pairing
The BBS# protocol can be implemented with or without pairings. However, current SE/HSM/TEE devices do not support such mathematical operations or the associated "pairing-friendly" curves. Therefore, the version without pairings is preferred for our various implementations on WSCD (SE/TEE).

The BBS# protocol without pairing requires assistance from the Issuer to obtain a proof of the issuer's signature validity, referred to in this document as **PoV_of_issuer_signature**. There are three options to obtain this proof:
- The Holder requests a signature validity proof for each presentation.
- The Verifier obtains the signature validity proofs from the Issuer.
- The Holder stores batches of signature validity proofs.

These three options are detailed below.

> Note : Even though advancements in quantum cryptography or other technologies may enable the breaking of certain encryption methods, BBS+ signatures, with or without pairing, are designed to be resilient against these threats, thereby ensuring [everlasting privacy](#135-everlasting-privacy).

### 4.1.1 Holder requests a signature validity proofs on each presentation
This option involves retrieving a **PoV_of_issuer_signature** from the Issuer of the presented attestation during the presentation process. 
Therefore, the wallet must be online to contact the Issuer for this proof.
To preserve the holder's privacy, the **PoV_of_issuer_signature** is obtained from the Issuer using the Oblivious Issuance Proof protocol (OIP) which is not detailed in this document.
The Issuer can verify the signature's correctness but cannot identify the attestation (and thus the holder) associated with this blinded signature.

The following sequence diagram illustrates the process of retrieving **PoV_of_issuer_signature** from the Issuer and sharing it with a verifier:

![Holder requests a signature validity proofs on each presentation](./media/1/pov-wallet.png)

**Flow description**
- [01]: This step represents the initial phase of the presentation process, which is not detailed in this context. At the end of this phase, the attestation Issuer's signature has been randomized for presentation to the Verifier.
- [02]: The Wallet generates a new random value, which is used solely to retrieve the Issuer's signature validity proof from the Issuer.
- [03]: The Wallet randomizes the blinded attestation Issuer's signature with the generated random value (**r_PoV**) to obtain a **double_blind_signature**. The validity of this double blind signature can be verified by the Issuer, but the Issuer cannot trace it back to the original signature or the issued attestation. The Issuer's signature is double-randomized because the **blind_signature** is shared with the Verifier at the end of the presentation process. This prevents user tracking based on the **blind_signature**, even if the Issuer and the Verifier collude.
- [04-06]: The Wallet sends the **double_blind_signature** to the Issuer to obtain a **blind_proof**. The exchanges between the Wallet and the Issuer are based on the Oblivious Issuance Proof protocol (OIP).
- [07-08]: The Wallet unblinds the **blind_proof** using the **r_PoV** random value. By unblinding the **blind_proof**, the Wallet obtains a proof corresponding to the **blind_signature**. The Wallet can then construct a **PoV_of_issuer_signature** that is not recognizable by the Issuer.
- [09-10]: The **PoV_of_issuer_signature** is sent to the Verifier, who can check the attestation Issuer's signature based on this proof.

### 4.1.2 Verifier obtain the signature validity proofs from the Issuer
This option allows the Verifier to directly contact the Issuer to retrieve the **PoV_of_issuer_signature** for the presented attestation signature. 
Therefore, the Verifier must be online to obtain this proof. 
To preserve the holder's privacy, the signature sent by the Verifier to the Issuer is blinded. 
The Issuer can verify the signature's correctness but cannot identify the attestation (and thus the holder) associated with this blinded signature.

The following sequence diagram illustrates the process of retrieving the **PoV_of_issuer_signature** from the issuer:

![Verifier obtain the signature validity proofs from the Issuer](./media/1/pov-verifier.png)

**Flow description**
- [01-02]: This step represents the initial phase of the presentation process, which is not detailed in this context.
- [03-04]: The wallet retrieves the Issuer signature for each attestation contained in the presentation and contacts the Issuer's attestation to obtain proof of the attestation signature's validity.
- [05]: The Issuer verifies the **blind_signature**. As the attestation signature has been randomized by the wallet during the presentation process, the issuer can verify the signature but cannot link it to an attestation that it has generated. Therefore, it cannot trace back to the holder of the attestation.
- [07-08]: The Issuer computes the **PoV_of_issuer_signature** and sends it to the verifier, who can then verify the validity of the presented attestation.
 
### 4.1.3 Holder stores batches of signature validity proofs
This option is recommended to enable the presentation of attestations to the verifier when the wallet is offline. The wallet retrieves several **PoV_of_issuer_signature** from the issuer, either after the attestation issuance or through a background process. These proofs can be used during the presentation to demonstrate the validity of the attestation signature to the verifier. To preserve the holder's privacy, each pre-provisioned proof must be used only once.

If the verifier colludes with the issuer, the issuer will not be able to recognize the **PoV_of_issuer_signature** due to the use of the Oblivious Issuance Proof protocol, which is not detailed in this document.

The following sequence diagram illustrates the process of retrieving **PoV_of_issuer_signature** from the Issuer and sharing it with a verifier:

![Holder stores batches of signature validity proofs](./media/1/pov-batch.png)

**Flow description**
- [01-03]: The wallet generates two random values to blind the issuer's signature. This double-blind signature can be verified by the issuer, but it cannot be traced back to the original signature or the issued attestation. The issuer's signature is double-randomized because the **blind_signature** (randomized only with **r_pres**) is shared with the verifier during the presentation process. This mechanism prevents user tracking based on the **blind_signature**, even if the issuer and the verifier collude. This blinding process is repeated **nb_of_proof** times, where **nb_of_proof** represents the number of validity proofs the wallet wishes to retrieve.
- [04-06]: The wallet sends the list of generated **double_blind_signature** values to the issuer to obtain a corresponding list of **blind_proof** values. The issuer generates as many **blind_proof** values as there are **double_blind_signature** values provided. The exchanges between the wallet and the issuer are conducted using the Oblivious Issuance Proof protocol (OIP).
- [07-09]: The wallet unblinds each **blind_proof** using the corresponding **r_PoV** random value. By unblinding the **blind_proof**, the wallet obtains a proof corresponding to the **blind_signature**. The wallet can then craft a **PoV_of_issuer_signature** that is not recognizable by the issuer. This unblinding process is also repeated **nb_of_proof** times. The wallet must store the crafted **PoV_of_issuer_signature** along with the corresponding **r_pres**, which will be used when the holder presents this attestation.
- [10-11]: Later, when the holder needs to present an attestation to a verifier and the wallet is offline, it can select a pre-provisioned issuer's signature validity proof (**PoV_of_issuer_signature**) along with its corresponding presentation random value (**r_pres**). The initial phase of the presentation process is not detailed in this context.
- [12]: The wallet uses the **r_pres** random value to blind the issuer's signature. At this stage, the wallet has an issuer **blind_signature** that can be verified using the **PoV_of_issuer_signature**.
- [13-14]: The **PoV_of_issuer_signature** is sent along with the presentation to the verifier, who can then validate the issuer's attestation signature based on this proof.

### 4.1.4 DDoS protection of Issuer's proof of validity APIs
It is crucial to protect access to the issuer's APIs that generate validity proofs for signatures. Since these APIs will be accessible on the Internet, attackers could launch denial-of-service (DDoS) attacks to disrupt the service. Furthermore, the process of validating issuer signatures involves not only software but also interactions with the issuer's WSCD (which protects the Issuer private keys). Therefore, it is not possible to simply address this issue by increasing capacity (horizontal scaling), for example.

To mitigate this risk, in addition to the basic DDoS protection mechanisms offered by cloud providers, consider the following proposals:
- __If the verifier obtains signature validity proofs from the issuer or if the holder stores batches of these proofs:__ Access to the issuer's APIs could be secured by requiring proof that the holder possesses a verifiable credential issued by the issuer. This proof could take the form of an anonymized verifiable presentation, following the process described in section [4.3](#43-attestation-presentation-flow), without disclosing any attributes of the attestation. The advantage of this approach is that it does not require interaction with the issuer's WSCD for verification.
- __If the holder requests a signature validity proof for each presentation:__ Access to the issuer's APIs could be protected by requiring proof that the verifier is a legitimate participant in the ecosystem, without revealing their identity. This proof could be structured as a zero-knowledge proof (ZKP).


## 4.2 Attestation issuance flow
This chapter delves into the attestation issuance flow, illustrating how various privacy and security mechanisms work together to ensure a secure and reliable process. For a better understanding of the overall sequence, the processes and mechanisms previously described in this document are not detailed here. References to the relevant chapters are provided for more information on the implementation.

![Attestation issuance flow](./media/1/issuance.png)

**Flow description**
- [01-11]: During the initial phase of the issuance process protocol a client authentication based on wallet authentication must be performed. These steps are not detailed in this context, but for mode information refer to the OpenID4VCI specification<sup>[[04](./Trust-model-Introduction.md#references)]</sup> and the OpenID4VC HAIP specification<sup>[[06](./Trust-model-Introduction.md#references)]</sup>. This authentication is not privacy-preserving, as there is no anonymization with the Issuer even if BBS# allow it. During these steps the Issuer must check the wallet attestation for non-revocation, non-expiration, signature validity, and the non-revocation or blacklisting of referenced WSCDs. At the end of this process, the Issuer provides the wallet with a token to access the credential API and a nonce to be referenced in the proof of possession of the holder's secret key. The Issuer must store the presented wallet attestation throughout the issuance transaction to include the WSCDs and wallet attestation reference in the issued attestation.
- [12]: The wallet builds the proof of possession of the holder's secret payload, using the nonce (from step [07]) and the Holder public key. Below is a non-normative example of a JWT proof of possession of the holder's secret at this step (named PoP_data in the diagram).
```
- Header:
{
  "typ": "openid4vci-proof+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<PK_holder_x>",
    "y": "<PK_holder_y>"
  }
}
- Payload:
{
  "aud": "https://credential-issuer.example.com",
  "iat": 1729237358,
  "nonce": "<nonce>"
}
```
- [13-17]: The wallet sends the PoP_data to the certified WSCD (e.g., an HSM) to sign it with the holder's private key. The generated **signature<sub>pk_holder</sub>** is an ECDSA signature on the **PoP_data**, which can be verified using **pk<sub>holder</sub>**. The wallet then crafts the proof of possession of the holder's secret and sends it, along with the previously retrieved token, to the Issuer to obtain the requested attestation.
- [18]: The Issuer verifies the validity of the proof of possession of the holder's secret and checks that this proof corresponds to the **wallet_attestation_presentation** shared with the Issuer during the client authentication process. Both elements must refer to the same **sk<sub>holder</sub>** to demonstrate that the attestation request originates from the same wallet that was authenticated during the wallet authentication phase.
- [19-21]: The Issuer constructs the attestation in accordance with our trust model requirements, including the computation of the attestation identifier (for more details, refer to the chapter [Attestation Identifier Computation](#23-attestation-identifier-computation)) and the addition of WSCDs and wallet attestation references retrieved from step [05] (for more details, refer to the chapter [Wallet and WSCDs References in Attestations During Issuance Process](#261-wallet-and-wscds-references-in-attestations-during-issuance-process)). The attestation is signed with the issuer's BBS+ secret_key (**sk<sub>issuer</sub>**). Since the solution is pairing-free, the signature is accompanied by a proof of validity (**PoV_of_issuer_signature**). Below is a non-normative example of an SD-JWT attestation generated by the Issuer with two Holder attributes:
```
- Header:
{
  "typ": "openid4vci-proof+jwt",
  "alg": "ES256",
  "kid": <issuer-key>
}
- Payload:
{
  "_sd": [
    "<DigestClaim1>",
    "<DigestClaim2>",
    "<DigestClaimWscdID>",
    "<DigestClaimWalletID>"
  ],
  "id": "<attestationId>"
  "iss": "https://issuer.example.com",
  "iat": 1729237358,
  "exp": 1829237358,
  "type": "https://credentials.example.com/VC_example",
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<PK_holder_x>",
      "y": "<PK_holder_y>"
    }
  }
}
- Signature:
<CredentialSignature>+<ProofOfValidityOfCredentialSignature>
- Disclosures:
<DisclosureOfClaim1>~<DisclosureOfClaim2>~<DisclosureOfClaimWscdID>~<DisclosureOfClaimWalletID>
```
- [22-24]: The Issuer must provide the wallet with all the information necessary to prove to a Verifier that the attestation is not revoked (for more details, refer to the chapter [Non revocation proof with accumulators](#252-non-revocation-proof-with-accumulators)) and not expired (for more details, refer to the chapter [Non expiration proof with accumulators](#251-non-expiration-proof-with-accumulators)) during the presentation flow. The information provided includes the current accumulator state used by the issuer to manage the revoked attestation list, the witness, and proof that all the provided information is valid. The same information must also be included for expiration. This information is computed by the issuer and sent along with the requested attestation to the wallet.
- [25-28]: The wallet verifies the received attestation and the attached proofs, then stores the attestation and the associated information for use during the presentation process.

The process may seem complex, but all BBS# steps involving randomization and other related tasks will be encapsulated in a BBS# library to facilitate easier implementation of this protocol.


## 4.3 Attestation presentation flow
This chapter delves into the attestation presentation flow, illustrating how various privacy and security mechanisms work together to ensure a secure and reliable process. For a better understanding of the overall sequence, the processes and mechanisms previously described in this document are not detailed here. References to the relevant chapters are provided for more information on the implementation.

Since the solution is pairing-free, as described in the chapter [validation of transaction when not using pairing](#41-validation-of-transaction-when-not-using-pairing), the Verifier requires assistance from the Issuer to obtain proof of the issuer's signature validity during the presentation process. Three options are available to retrieve this proof. In the flow presented below, we use the option where [the Verifier obtains the signature validity proofs from the issuer](#412-verifier-obtain-the-signature-validity-proofs-from-the-issuer).

![Attestation presentation flow](./media/1/presentation.png)

**Flow description**
- [01]: During the initial phase of the presentation process protocol, the verifier retrieves the Verifier request. These steps are not detailed in this context. For more information, refer to the OpenID4VP specification<sup>[[05](./Trust-model-Introduction.md#references)]</sup>. During this exchange with the Verifier, the Wallet retrieves a **nonce** that must be included in the presentation to prevent replay attacks.
- [02-05]: The Wallet randomizes the **pk<sub>holder</sub>** and the attestation **signature<sub>issuer</sub>** (for more details on the randomization process, refer to the chapter [Holder Public key and Issuer signature randomization during the presentation process](#24-holder-public-key-and-issuer-signature-randomization-during-the-presentation-process)).
- [06]: For each undisclosed claim, the Wallet replaces the corresponding digests with static values to prevent holder tracking based on digest, and generates the related commitments and proofs (for more details, refer to the chapter [Static undisclosed digest](#21-static-undisclosed-digest)).
- [07]: For each trackable attestation attribute, the Wallet replaces the values with static values and generates the related commitments and proofs using the same process as in the previous step.
- [08-09]: The Wallet refreshes the attestation using all previously generated elements. It also generates a global proof that is included in the attestation Issuer signature to maintain compatibility with standard formats (for more details, refer to the chapter [Description of proofs during presentation](#44-description-of-proofs-during-presentation)). The **attestation_integrity_ZKP** proves that the refreshed attestation is consistent with the original attestation.
- [10-17]: The Wallet generates the following non-expiration and non-revocation proofs: 
  - A proof (**non_attestation_expiration_zkp**) that the attestation is not expired without disclosing the attestation's validity date, which could be used to track the Holder (for more details, refer to the chapter [Non-expiration proof with accumulators](#251-non-expiration-proof-with-accumulators))
  - A proof (**non_WSCD_revocation_zkp**) that the attestation is not revoked without disclosing the attestation's identifier which could be used to track the Holder (for more details, refer to the chapter [Non-revocation proof with accumulators](#252-non-revocation-proof-with-accumulators))
  - Proofs (**non_wallet_attestation_revocation_zkp** and **non_attestation_revocation_zkp**) that the WSCD and the wallet's attestation referenced in the attestation are not revoked without disclosing the corresponding references (for more details, refer to the chapter [Wallet and WSCDs references in attestations during presentation process](#262-wallet-and-wscds-references-in-attestations-during-presentation-process))
- [18]: The Wallet refreshes the attestation with the previously generated proofs. Below is a non-normative example of an SD-JWT attestation with two Holder attributes, but only one disclosed, at this step:
```
- Header:
{
  "typ": "dc+sd-jwt",
  "alg": "ES256",
  "kid": <issuer-key>
}
- Payload:
{
  "_sd": [
    "<DigestClaim1>",
    "0000000000000000000000000000000000000000000", //Claim2
    "0000000000000000000000000000000000000000000", //ClaimWscdID>
    "0000000000000000000000000000000000000000000"  //ClaimWalletID
  ],
  "id": "<AttestationIdentifierCommitment>"
  "iss": "https://issuer.example.com",
  "iat": 0, //Replaced by Jan 01 1970
  "exp": 0, //Replaced by Jan 01 1970
  "type": "https://credentials.example.com/VC_example",
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<PK_blind_holder_x>",
      "y": "<PK_blind_holder_y>"
    }
  }
}
- Signature:
<blind_signature_issuer>+<attestation_integrity_ZKP>+<non_attestation_expiration_zkp>+<non_WSCD_revocation_zkp>+<non_wallet_attestation_revocation_zkp>+<non_attestation_revocation_zkp>
- Disclosures:
<DisclosureOfClaim1>
```
- [19-24]: The Wallet crafts the presentation, including the refreshed attestation previously generated, and signs it with their WSCD. The Wallet then blinds the signature to obtain a signature that can be verified with the blinded Holder's public key (for more details on the randomization process, refer to the chapter [Holder Public key and Issuer signature randomization during the presentation process](#24-holder-public-key-and-issuer-signature-randomization-during-the-presentation-process)).Below is a non-normative example of the verifiable presentation of the refreshed SD-JWT attestation:
```
- Credential:
<refreshed_attestation> \\@see step 18
- Key binding payload:
{
  "nonce": "1234567891",
  "aud": "https://example.com/verifier",
  "iat": 1733230141,
  "sd_hash": "HVV0BpnEL....Z5V8"
}
- Key binding signature:
<blind_signature_holder>+<key_binding_zkp>
```
- [25-26]: The Wallet sends the presentation to the Verifier, who can  then verify it.
- [27-32]: As the solution is pairing-free, the Verifier cannot check the validity of non-revocation, non-expiration and Issuer's signature. Three options are available to retrieve these proofs of validity. In this flow, we use the option : Verifier obtain the signature validity proofs from the Issuer (for more details on the three options, refer to the chapter [Validation of transaction when not using pairing](#41-validation-of-transaction-when-not-using-pairing)).


## 4.4 Description of proofs during presentation 
To maintain compatibility with standard formats, we incorporate all additional proofs generated by the BBS# mechanisms into the attestation's and presentation's signatures. These proofs are essential for ensuring privacy while adhering to established standards. Therefore, it is necessary to describe the format of signatures in detail to fully understand all the elements that compose it.

### 4.4.1 Description of the attestation signature
The following diagram illustrates the content of the **attestation signature** field during the presentation process:

![Attestation presentation flow](./media/1/zkp-attestation.png)

- **Randomized attestation issuer signature**: This element corresponds to the initial attestation signature that has been randomized. Since the Issuer uses BBS+ signatures without pairing, this signature requires assistance from the Issuer for verification. This signature is also integrated into the attestation integrity proof and can be extracted from it. However, for better comprehension of the functional flows, the signature is duplicated.
- **Proof of the attestation integrity**: This proof demonstrated that : 
  - The randomized Issuer signature is related to the attestation data, which includes the blinded Holder's public key, the disclosed and undisclosed claims, the undisclosed attestation identifier, the creation date, and the expiration date.
  - The Holder knows a public key and a random value such that applying this random to the Holder's public key results in the blinded Holder's public key referenced in the presented attestation.
  - The Holder knows a signature and a random value such that applying this random to the Issuer's signature results in the blinded Issuer's signature.
- **Proof of attestation non-revocation**: This proof demonstrates that the attestation has not been revoked by the issuer without revealing the attestation identifier. It relies on an accumulator that contains references to all non-revoked attestations (depending on whether the revocation list is a whitelist or a blacklist). By showing that the attestation is included in this list, it can be confirmed that it remains valid. Since the accumulators are pairing-free, this proof must be presented to the accumulator owner for verification.
- **Proof of attestation non-expiration**: This proof demonstrates that the attestation is not expired without revealing the attestation expiration date. It relies on an accumulator that contains references to all expired dates. By showing that the attestation expiration date is not included in this list, it can be confirmed that it remains valid. Since the accumulators are pairing-free, this proof must be presented to the accumulator owner for verification.
- **Proof of non-revocation of the WSCD referenced in the attestation**: This proof demonstrates that the WSCD referenced in the attestation has not been revoked without revealing the WSCD reference itself. It relies on an accumulator that contains references to all non-revoked WSCDs (depending on whether the revocation list is a whitelist or a blacklist). By showing that the WSCD reference is included in this list, it can be confirmed that the WSCD, which stores the holder's private key and is used for attestation key binding, remains valid. Since the accumulators are pairing-free, this proof must be presented to the accumulator owner for verification.
- **Proof of non-revocation of the Wallet referenced in the attestation**: This proof demonstrates that the Wallet referenced in the attestation has not been revoked without revealing the Wallet reference itself. It relies on an accumulator that contains references to all non-revoked Wallet (depending on whether the revocation list is a whitelist or a blacklist). By showing that the Wallet reference is included in this list, it can be confirmed that the Wallet used by the holder to store and share the attestation remains valid. Since the accumulators are pairing-free, this proof must be presented to the accumulator owner for verification.

### 4.4.1 Description of the presentation signature
The following diagram illustrates the content of the **presentation signature** field during the presentation process:

![Attestation presentation flow](./media/1/zkp-key-binding.png)

- **Randomized presentation holder's signature**: This element corresponds to the Holder's signature on the presentation elements that has been randomized. This signature is also integrated into the key binding proof and can be extracted from it. However, for better comprehension of the functional flows, the signature is duplicated.
- **Proof of the key binding**: This proof demonstrated that 
  - the Holder knows a public key and a random value such that applying this random to the Holder's public key results in the blinded Holder's public key referenced in the presented attestation(s).
  - The Holder knows a signature and a random value such that applying this random to the Holder's signature results in the blinded Holder's signature.
