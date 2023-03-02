# Abstract

This document defines requirements for a baseline time-stamp policy
for Time-Stamping Authorities (TSAs) issuing time-stamp tokens,
supported by public key certificates, with an accuracy of one second
or better. A TSA may define its own policy which enhances the policy
defined in this document. Such a policy shall incorporate or further
constrain the requirements identified in this document.

# 1. Introduction

The content of this RFC is based on [RFC 3628](https://datatracker.ietf.org/doc/html/rfc3628).
The primary changes in this RFC are the removal of legal requirements,
requirements to comply with the EU Directive, and requirements that specify the
TSA will use on-premise hardware to manage the TSA primary key and service.

In creating reliable and manageable digital evidence it is necessary to have an
agreed upon method of associating time data to transaction so that they might be
compared to each other at a later time. The quality of this evidence is based on
creating and managing the data structure that represent the events and the
quality of the parametric data points that anchor them to the real world.
In this instance this being the time data and how it was applied.

A typical transaction is a digitally signed document, where it is
necessary to prove that the digital signature from the signer was
applied when the signer's certificate was valid.

A timestamp or a time mark (which is an audit record kept in a secure
audit trail from a trusted third party) applied to a digital
signature value proves that the digital signature was created before
the date included in the time-stamp or time mark.

To prove the digital signature was generated while the signer's
certificate was valid, the digital signature must be verified and the
following conditions satisfied:

1. the time-stamp (or time mark) was applied before the end of the
   validity period of the signer's certificate,
1. the time-stamp (or time mark) was applied either while the signer's
   certificate was not revoked or before the revocation date of the certificate.

Thus a time-stamp (or time mark) applied in this manner proves that
the digital signature was created while the signer's certificate was
valid. This concept proves the validity of a digital signature over
the whole of any certificate chain.

Policy requirements to cover that case is the primary reason of this
document. However, it should be observed that these policy
requirements can be used to address other needs.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[BCP 14](https://datatracker.ietf.org/doc/html/bcp14),
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

# 2. Overview

These policy requirements are aimed at time-stamping services used in
support of qualified electronic signatures but may be applied to any application
requiring to prove that a datum existed before a particular time.

These policy requirements are based on the use of public key
cryptography, public key certificates and reliable time sources. The
present document may be used by independent bodies as the basis for
confirming that a TSA may be trusted for providing time-stamping
services.

This document addresses requirements for synchronizing TSAs issuing
time-stamp tokens with Coordinated universal time (UTC) and digitally
signed by TSUs.

Subscriber and relying parties should consult the TSA's practice
statement to obtain further details of precisely how this time-stamp
policy is implemented by the particular TSA (e.g., protocols used in
providing this service).

This document does not specify:

- protocols used to access the TSUs;

NOTE 1: A time-stamping protocol is defined in
[RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161)
and profiled in [TS 101 861](https://www.etsi.org/deliver/etsi_ts/101800_101899/101861/01.04.01_60/ts_101861v010401p.pdf).

- how the requirements identified herein may be assessed by an independent body;
- requirements for information to be made available to such independent bodies;
- requirements on such independent bodies.

# 3. Definitions and Abbreviations

## 3.1. Definitions

For the purposes of the present document, the following terms and
definitions apply:

- relying party: recipient of a time-stamp token who relies on that time-stamp token.

- subscriber: entity requiring the services provided by a TSA and which has
  explicitly or implicitly agreed to its terms and conditions.

- time-stamp token: data object that binds a representation of a datum to a
  particular time, thus establishing evidence that the datum existed before that time.

- time-stamping authority: authority which issues time-stamp tokens.

- TSA Disclosure statement: set of statements about the policies and practices
  of a TSA that particularly require emphasis or disclosure to subscribers and
  relying parties, for example to meet regulatory requirements.

- TSA practice statement: statement of the practices that a TSA employs
  in issuing time-stamp tokens.

- TSA system: composition of IT products and components organized to support
  the provision of time-stamping services.

- time-stamp policy: named set of rules that indicates the applicability of a
  time-stamp token to a particular community and/or class of application with
  common security requirements.

- time-stamping unit: set of hardware and software which is managed as a unit
  and has a single time-stamp token signing key active at a time.

- Coordinated Universal Time (UTC): Time scale based on the second as defined
  in ITU-R Recommendation TF.460-5.

  NOTE: For most practical purposes UTC is equivalent to mean
  solar time at the prime meridian. More specifically, UTC is a
  compromise between the highly stable atomic time (Temps
  Atomique International - TAI) and solar time derived from the irregular Earth
  rotation (related to the Greenwich mean sidereal time (GMST) by
  a conventional relationship).

- UTC(k): Time-scale realized by the laboratory "k" and kept in close
  agreement with UTC, with the goal to reach plus or minus 100
  ns. (See ITU-R Recommendation TF.536-1.

        NOTE:  A list of UTC(k) laboratories is given in section 1 of
        Circular T disseminated by BIPM and available from the BIPM
        website (http://www.bipm.org/).

## 3.2. Abbreviations

For the purposes of the present document, the following abbreviations
apply:

- TSA Time-Stamping Authority
- TSU Time-Stamping Unit
- TST Time-Stamp Token
- UTC Coordinated Universal Time

# 4. General Concepts

## 4.1. Time-Stamping Services

The provision of time-stamping services is broken down into the
following component services for the purposes of classifying
requirements:

- Time-stamping provision: This service component generates time-stamp tokens.

- Time-stamping management: The service component that monitors and controls
  the operation of the time-stamping services to ensure that the service is
  provided as specified by the TSA. This service component is responsible for
  the installation and de-installation of the time-stamping provision service.
  For example, time-stamping management ensures that the clock used for
  time-stamping is correctly synchronized with UTC.

This subdivision of services is only for the purposes of clarifying
the requirements specified in the current document and places no
restrictions on any subdivision of an implementation of time-stamping
services.

## 4.2. Time-Stamping Authority

The authority to issue time-stamp tokens, trusted by the users of the
time-stamping services, i.e., subscribers and relying parties, is
called the Time-Stamping Authority (TSA).

TSA has overall
responsibility for time-stamping services identified in clause 4.1.
The TSA has responsibility for the operation of one or more TSU's
which creates and signs on behalf of the TSA. The TSA responsible
for issuing a time-stamp token is identifiable (see 7.3.1 h).

The TSA may delegate the signing of timestamps to a cloud key management
service. However, the TSA always maintains overall responsibility and ensures
that the policy requirements identified in the present document are met.

A TSA may operate several identifiable time-stamping units.
Each unit has a different key.

A TSA is a certification-service-provider which issues time-stamp tokens.

## 4.3.Subscriber

The subscriber may be an organization comprising several end-users or an
individual end-user.

When the subscriber is an organization, some of the obligations that apply to
that organization will have to apply as well to the end-users.

In any case the organization will be held responsible if the
obligations from the end-users are not correctly fulfilled and therefore the
organization is expected to suitably inform its end users.

When the subscriber is an end-user, the end-user will be held directly
responsible if its obligations are not correctly fulfilled.

## 4.4. Time-Stamp Policy and TSA Practice Statement

This section explains the relative roles of Time-stamp policy and TSA
practice statement. It places no restriction on the form of a time-
stamp policy or practice statement specification.

### 4.4.1. Purpose

In general, the time-stamp policy states "what is to be adhered to,"
while a TSA practice statement states "how it is adhered to", i.e.,
the processes it will use in creating time-stamps and maintaining the accuracy
of its clock.

The relationship between the time-stamp policy and TSA practice statement is
similar in nature to the relationship of other business policies which state
the requirements of the business, while operational units define the practices
and procedures of how these policies are to be carried out.

The present document specifies a time-stamp policy to meet general
requirements for trusted time-stamping services.
TSAs specify in TSA practice statements how these requirements are met.

### 4.4.2. Level of Specificity

The TSA practice statement is more specific than a time-stamp policy.

A TSA practice statement is a more detailed description of the terms
and conditions as well as business and operational practices of a TSA
in issuing and otherwise managing time-stamping services.

The TSA practice statement of a TSA enforces the rules established by a
time-stamp policy. A TSA practice statement defines how a specific
TSA meets the technical, organizational and procedural requirements
identified in a time-stamp policy.

NOTE: Even lower-level internal documentation may be appropriate for
a TSA detailing the specific procedures necessary to complete the
practices identified in the TSA practice statement.

### 4.4.3. Approach

The approach of a time-stamp policy is significantly different from a
TSA practice statement.

A time-stamp policy is defined independently of the specific details of the
specific operating environment of a TSA, whereas a TSA practice statement is
tailored to the organizational structure, operating procedures, facilities,
and computing environment of a TSA.

A time-stamp policy may be defined by the user of times-stamp services,
whereas the TSA practice statement is always defined by the provider.

# 5. Time-Stamp Policies

## 5.1. Overview

A time-stamp policy is a "named set of rules that indicates the
applicability of a time-stamp token to a particular community and/or
class of application with common security requirements" (see clauses
[3.1](#31-definitions) and [4.4](#44-time-stamp-policy-and-tsa-practice-statement)).

The present document defines requirements for a baseline time-stamp
policy for TSAs issuing time-stamp tokens, supported by public key
certificates, with an accuracy of 1 second or better.

NOTE 1: Without additional measures the relying party may not be able to ensure
the validity of a time-stamp token beyond the end of the validity period of the
supporting certificate. See Annex A on verification of the validity of a
time-stamp token beyond the validity period of the TSU's certificate.

A TSA may define its own policy which enhances the policy defined in this
document. Such a policy shall incorporate or further constrain the requirements
identified in this document.

NOTE 1: It is required that a time-stamp token includes an identifier
for the applicable policy (see section [7.3.1](#731-time-stamp-token)).

## 5.2. Identification

The object-identifier X.208 of this time-stamp policy is `1.3.6.1.4.1.57264.2`.
In the TSA disclosure statement made available to subscribers and relying
parties, a TSA shall also include the identifier for the time-stamp policy
to indicate its conformance.

## 5.3. User Community and Applicability

This service aims to provide binary transparency. This policy may be used for
public time-stamping services or time-stamping services used
within a closed community.

## 5.4. Conformance

The TSA shall use the identifier for the timestamp policy in timestamp tokens
as given in section [5.2](#52-identification), or define its own time-stamp
policy that incorporates or further constrains the requirements identified
in the present document:

- If the TSA claims conformance to the identified timestamp policy and makes
  available to subscribers and relying parties on request the evidence to
  support the claim of conformance; or

- If the TSA has been assessed to conform to the identified timestamp
  policy by an independent party.

A conformant TSA must demonstrate that:

- It meets its obligations as defined in section [6.1](#61-tsa-obligation);

- It has implemented controls which meet the requirements specified in
  section [7](#7-requirements-on-tsa-practices).

# 6. Obligations and Liability

## 6.1. TSA Obligations

### 6.1.1. General

The TSA shall ensure that all requirements on TSA, as detailed in section
[7](#7-requirements-on-tsa-practices), are implemented as applicable to the
selected trusted time-stamp policy.

The TSA shall ensure conformance with the procedures prescribed in this policy,
even when the TSA functionality is undertaken by subcontractors.

The TSA shall also ensure adherence to any additional obligations indicated in
the time-stamp either directly or incorporated by reference.

The TSA shall provide all its time-stamping services consistent with
its practice statement.

### 6.1.2. TSA Obligations Towards Subscribers

The TSA shall meet its claims as given in its terms and conditions including
the availability and accuracy of its service.

## 6.2. Subscriber Obligations

The current document places no specific obligations on the subscriber beyond
any TSA specific requirements stated in the TSA's terms and condition.

NOTE: It is advisable that, when obtaining a time-stamp token, the subscriber
verifies that the time-stamp token has been correctly signed and that the
private key used to sign the time-stamp token has not been compromised.

## 6.3. Relying Party Obligations

The terms and conditions made available to relying parties shall include an 
obligation on the relying party that, when relying on a time-stamp token, it shall:

1. verify that the time-stamp token has been correctly signed and that the
   private key used to sign the time-stamp has not been compromised
   until the time of the verification;

   NOTE: During the TSU's certificate validity period, the validity
   of the signing key can be checked using current revocation status
   for the TSU's certificate. If the time of verification exceeds
   the end of the validity period of the corresponding certificate,
   see annex A for guidance.

1. take into account any limitations on the usage of the time-stamp
   indicated by the time-stamp policy;

1. take into account any other precautions prescribed in agreements or elsewhere.

# 7. Requirements on TSA Practices

The TSA shall implement the controls that meet the following requirements.

These policy requirements are not meant to imply any restrictions on charging
for TSA services.

The requirements are indicated in terms of the security objectives, followed by
more specific requirements for controls to meet those objectives where it is
necessary to provide confidence that those objective will be met.

NOTE: The details of controls required to meet an objective is a balance
between achieving the necessary confidence whilst minimizing the restrictions
on the techniques that a TSA may employ in issuing time-stamp tokens.
In the case of section [7.4](#74-tsa-management-and-operation)
(TSA management and operation), a reference is made to a source of more
detailed control requirements. Due to these factors the specificity of the
requirements given under a given topic may vary.

The provision of a time-stamp token in response to a request is at the
discretion of the TSA depending on any service level agreements with the subscriber.

## 7.1. Practice and Disclosure Statements

### 7.1.1. TSA Practice Statement

The TSA shall ensure that it demonstrates the reliability necessary
for providing time-stamping services.

In particular:

1.  The TSA shall have a risk assessment carried out in order to evaluate
  business assets and threats to those assets in order to determine the necessary security controls and operational procedures.

1. The TSA shall have a statement of the practices and procedures used to
  address all the requirements identified in this time-stamp policy.

   - NOTE 1: This policy makes no requirement as to   the structure
  of the TSA practice statement.

1. The TSA's practice statement shall identify the obligations of all
  external organizations supporting the TSA services including
  the applicable policies and practices.

1. The TSA may make available to subscribers and relying parties its practice
  statement, and other relevant documentation, as necessary, to assess 
  conformance to the time-stamp policy.

   - NOTE 2: The TSA is not generally required to make all the details
  of its practices public.

1. Maintainers of the TSA shall have final authority for approving the TSA
  practice statement and ensuring that the practices are properly implemented.
  Maintainers shall also review any changes to the TSA to confirm that they
  follow the approved practice statement.

1. The TSA shall give due notice of changes it intends to make in its practice
  statement and shall, following approval as in (5) above, make the revised
  TSA practice statement immediately available as required under (4) above.

## 7.2. Key Management Life Cycle

### 7.2.1. TSA Key Generation

The TSA shall ensure that any cryptographic keys are generated in
under controlled circumstances.

In particular:

1. The generation of the TSU's signing key(s) shall be undertaken by personnel
   in trusted roles. The personnel authorized to carry out this function shall
   be limited to those requiring to do so under the TSA's practices.

1. The generation of the TSU's signing key(s) shall be carried out in a secure
   environment. It MAY be carried out in a cloud based environment
   that protects the key.

1. The TSU key generation algorithm, the resulting signing key length and
   signature algorithm used for signing time-stamp tokens key shall be
   recognized by TSA maintainers as being fit for the purposes of time-stamp
   tokens as issued by the TSA.

### 7.2.2. TSU Private Key Protection

The TSA shall ensure that TSU private keys remain confidential and maintain
their integrity. The TSU private signing key shall be securely
stored in one of the following:

- HSM
- Cloud environment
- On-prem environment with controlled access

### 7.2.3. TSU Public Key Distribution

The TSA shall ensure that the integrity and authenticity of the TSU signature
verification (public) keys and any associated parameters are maintained
during its distribution to relying parties.

In particular:

1. TSU signature verification (public) keys shall be made available to relying
   parties in a public key certificate.

   NOTE: For example, TSU's certificates may be issued by a certification
   authority operated by the same organization as the TSA,
   or issued by another authority.

1. The TSU's signature verification (public) key certificate shall be issued
   by a certification authority operating under a certificate policy which
   provides a level of security equivalent to, or higher than,
   this time-stamping policy.

### 7.2.4. Rekeying TSU's Key

The life-time of TSU's certificate shall be not longer than the period of
time that the chosen algorithm and key length is recognized as being
fit for purpose (see section [7.2.1c](#721-tsa-key-generation))).

NOTE 1: The following additional considerations apply when limiting
that lifetime:

- Should a TSU private key be compromised, then the longer the life-time,
  the more affected time-stamp tokens there will be.

NOTE 2: TSU key compromise does not only depend on the characteristics of
the storage system being used but also on the procedures being used at system
initialization and key export (when that function is supported).

### 7.2.5. End of TSU Key Life Cycle

The TSA shall ensure that TSU private signing keys are not used
beyond the end of their life cycle.

In particular:

1. Operational or technical procedures shall be in place to ensure that a
   new key is put in place when a TSU's key expires.

1. The TSU private signing keys, or any key part, including any copies shall
   be destroyed such that the private keys cannot be retrieved.

1. The TST generation system SHALL reject any attempt to issue TSTs
   if the signing private key has expired.

### 7.2.6. Life Cycle Management of the Cryptographic Module used to Sign Time-Stamps

The TSA shall use one of the following to host the token signing software:

- HSM
- Cloud environment
- On-prem environment with controlled access

## 7.3. Time-Stamping

### 7.3.1. Time-Stamp Token

The TSA shall ensure that time-stamp tokens are issued securely and include the correct time.

In particular:

1. The time-stamp token shall include an identifier for the time-stamp policy.

1. Each time-stamp token shall have a unique identifier.

1. The time values the TSU uses in the time-stamp token shall be traceable to
   at least one of the real time values distributed by a UTC(k) laboratory.

1. The time-stamp provider should periodically monitor its correctness of time 
   with a set of trusted UTC sources. The recorded accuracy should be included 
   in the returned time-stamp token.

1. The time-stamp provider SHOULD monitor for accuracy and alert if it's found 
   to be out of sync.

1. The time-stamp token shall include a representation (e.g., hash value) of
   the datum being time-stamped as provided by the requestor.

1. The time-stamp token shall be signed using a key generated exclusively
   for this purpose.

   NOTE 1: A protocol for a time-stamp token is defined in RFC 3631 and
   profiled in TS 101 861.

   NOTE 2: In the case of a number of requests at approximately the same time,
   the ordering of the time within the accuracy of the TSU clock is not mandated.

1. The time-stamp token shall include:
   - where applicable, an identifier for the country in which
     the TSA is established;
   - an identifier for the TSA;
   - an identifier for the unit which issues the time-stamps.

### 7.3.2. Clock Synchronization with UTC

The TSA shall ensure that its clock is synchronized with UTC
within the declared accuracy.

In particular:

1. The calibration of the TSU clocks shall be maintained such that the
   clocks shall not be expected to drift outside the declared accuracy.

1. The TSA shall ensure that, if the time that would be indicated in a
   time-stamp token drifts or jumps out of synchronization with UTC,
   this will be detected (see also [7.3.1e](#731-time-stamp-token))).

   NOTE 1: Relying parties are required to be informed of such events
   (see section [7.4.8](#748-compromise-of-tsa-services)).

1. The TSA shall ensure that clock synchronization is maintained when a
   leap second occurs as notified by the appropriate body. The change to take
   account of the leap second shall occur during the last minute of the day
   when the leap second is scheduled to occur.

   NOTE 1: A leap second is an adjustment to UTC by skipping or adding an
   extra second on the last second of a UTC month. First preference is given
   to the end of December and June, and second preference is given to the end
   of March and September.

## 7.4. TSA Management and Operation

### 7.4.1. Security Management

The TSA shall ensure that the administrative and management procedures applied
are adequate and correspond to recognized best practice.

In particular:

TSA General

1. The TSA shall retain responsibility for all aspects of the provision of
   time-stamping services within the scope of this time-stamp policy,
   whether or not functions are outsourced to subcontractors.
   Responsibilities of third parties shall be clearly defined by the TSA
   and appropriate arrangements made to ensure that third parties are bound
   to implement any controls required by the TSA. The TSA shall retain
   responsibility for the disclosure of relevant practices of all parties.

1. The TSA management shall provide direction on information security
   through a suitable high level steering forum that is responsible for
   defining the TSA's information security policy. The TSA shall ensure
   publication and communication of this policy to all employees who are
   impacted by it.

1. The information security infrastructure necessary to manage the security
   within the TSA shall be maintained at all times. Any changes that will
   impact on the level of security provided shall be approved
   by the TSA management forum.

1. The security controls and operating procedures for TSA systems and
   information assets providing the time-stamping services shall be documented,
   implemented and maintained.

   NOTE 1: The present documentation (commonly called a system
   security policy or manual) should identify all relevant targets,
   objects and potential threats related to the services provided and
   the safeguards required to avoid or limit the effects of those
   threats. It should describe the rules, directives and procedures regarding 
   how the specified services and the associated security assurance are granted 
   in addition to stating policy on incidents and disasters.

- TSA shall ensure that the security of information is maintained when the
  responsibility for TSA functions has been outsourced to another
  organization or entity.

### 7.4.2. Asset Classification and Management

The TSA shall ensure that its information and other assets receive an
appropriate level of protection.

In particular:

- The TSA shall maintain an inventory of all assets and shall assign a
  classification for the protection requirements to those assets consistent
  with the risk analysis.

### 7.4.3. Personnel Security

The TSA shall follow the principle of least privilege and ensure that those
working on the TSA only have the minimal privilege needed to perform functions.

### 7.4.4. Physical and Environmental Security

Ths TSA will host the timestamping authority service and store private keys
with either on-prem hardware or a trusted cloud provider. If the TSA uses a
cloud provider to host the service and private key, it shall ensure it uses a
provider that has appropriate physical security settings.

For both the time-stamping provision and the time-stamping management:

- The TSA shall only use cloud providers that control physical access to
  facilities that will host the timestamping authority service and private key;

- The TSA shall implement controls to avoid loss, damage or compromise of
  assets and interruption to business activities;

- controls shall be implemented to avoid compromise or theft of information.

- The following additional controls shall be applied to time-stamping management:
  - The TSA shall ensure it uses a cloud provider that keeps infrastructure
    in an environment which physically protects the services from compromise through unauthorized access to systems or data.

### 7.4.5. Operations Management

The TSA shall ensure that the TSA system components are secure and
correctly operated, with minimal risk of failure. In particular (general):

1. The integrity of TSA system components and information shall be protected
   against viruses, malicious and unauthorized software.

1. Incident reporting and response procedures shall be employed in such a way
   that damage from security incidents and malfunctions shall be minimized.

1. Media used within the TSA trustworthy systems shall be securely handled to
   protect media from damage, theft, unauthorized access and obsolescence.

   NOTE 1: Every member of personnel with management responsibilities is
   responsible for planning and effectively implementing the time-stamp
   policy and associated practices as documented in the TSA practice statement.

1. Procedures shall be established and implemented for all trusted and
   administrative roles that impact on the provision of time-stamping services.

Media handling and security:

1. All media shall be handled securely in accordance with requirements of the
   information classification scheme (see section
   [7.4.2](#742-asset-classification-and-management)). Media containing
   sensitive data shall be securely disposed of when no longer required.

System Planning:

1. Capacity demands shall be monitored and projections of future capacity 
   requirements made to ensure that adequate processing power and storage 
   are available.

Incident reporting and response:

1. The TSA shall act in a timely and coordinated manner in order to respond
   quickly to incidents and to limit the impact of breaches of security.
   All incidents shall be reported as soon as possible after the incident.

The following additional controls shall be applied to time-stamping
management:

Operations procedures and responsibilities

1. TSA security operations shall be separated from other operations.
   NOTE 1: TSA security operations' responsibilities include: - operational
   procedures and responsibilities; - secure systems planning and acceptance;
   - protection from malicious software; - housekeeping; - network management;
   - active monitoring of audit journals, event analysis and follow-up;
   - media handling and security; - data and software exchange.

These operations shall be managed by TSA trusted personnel, as defined within
the appropriate security policy, and, roles and responsibility documents.

### 7.4.6. System Access Management

The TSA shall ensure that TSA system access is limited to
properly authorized individuals.

In particular (general):

1. Controls (e.g., firewalls) shall be implemented to protect the TSA's
   internal network domains from unauthorized access including access by
   subscribers and third parties.

   NOTE: Firewalls should also be configured to prevent all protocols and
   accesses not required for the operation of the TSA.

1. The TSA shall ensure effective administration of user (this includes
   operators, administrators and auditors) access to maintain system security,
   including user account management, auditing and timely modification
   or removal of access.

1. The TSA shall ensure that access to information and application system
   functions is restricted in accordance with the access control policy and
   that the TSA system provides sufficient computer security controls for the
   separation of trusted roles identified in TSA's practices, including the
   separation of security administrator and operation functions.
   Particularly, use of system utility programs is restricted
   and tightly controlled.

1. TSA personnel shall be accountable for their activities

The following additional controls shall be applied to time-stamping
management:

1. The TSA shall ensure that it uses a cloud provider that keeps local network
   components (e.g., routers) in a physically secure environment.

### 7.4.7. Trustworthy Systems Deployment and Maintenance

The TSA shall use trustworthy systems and products that are protected
against modification.

NOTE: The risk analysis carried out on the TSA's services (see section
[7.1.1](#711-tsa-practice-statement)) should identify its critical services
requiring trustworthy systems and the levels of assurance required.

In particular:

- An analysis of security requirements shall be carried out at the design
  and requirements specification stage of any systems development project
  undertaken by the TSA or on behalf of the TSA to ensure that security is
  built into IT systems.

- Change control procedures shall be applied for releases, modifications and
  emergency software fixes of any operational software.

### 7.4.8. Compromise of TSA Services

The TSA shall ensure in the case of events which affect the security of the
TSA's services, including compromise of TSU's private signing keys or
detected loss of calibration, that relevant information is made available to
subscribers and relying parties.

In particular:

1. The TSA's disaster recovery plan shall address the compromise or suspected
   compromise of TSU's private signing keys or loss of calibration of a
   TSU clock, which may have affected time-stamp tokens which have been issued.

1. In the case of a compromise, or suspected compromise or loss of
   calibration the TSA shall make available to all subscribers and relying
   parties a description of compromise that occurred.

1. In the case of compromise to a TSU's operation (e.g., TSU key compromise),
   suspected compromise or loss of calibration the TSU shall not issue
   time-stamp tokens until steps are taken to recover from the compromise.

- In case of major compromise of the TSA's operation or loss of calibration,
  wherever possible, the TSA shall make available to all subscribers and
  relying parties information which may be used to identify the time-stamp
  tokens which may have been affected, unless this breaches the privacy of
  the TSAs users or the security of the TSA services.

  NOTE: In case the private key does become compromised, an audit trail of
  all tokens generated by the TSA may provide a means to discriminate between
  genuine and false backdated tokens. Two time-stamp tokens from two
  different TSAs may be another way to address this issue.

### 7.4.9. TSA Termination

The TSA shall ensure that potential disruptions to subscribers and relying
parties are minimized as a result of the cessation of the TSA's time-stamping
services, and in particular ensure continued maintenance of information
required to verify the correctness of time-stamp tokens.

In particular:

1. Before the TSA terminates its time-stamping services the following
   procedures shall be executed as a minimum:

   - the TSA shall make available to all subscribers and relying parties
     information concerning its termination;

   - TSA shall terminate authorization of any outside services
     performing key singing

   - the TSA shall maintain or transfer to a reliable party its obligations
     to make available its public key or its certificates to relying parties for a reasonable period;

   - TSU private keys, including backup copies, shall be destroyed in a
     manner such that the private keys cannot be retrieved.

1. The TSA shall state in its practices the provisions made for
   termination of service. This shall include:

   - notification of affected entities;
   - transferring the TSA obligations to other parties.

1. The TSA shall take steps to have the TSU's certificates revoked.

# 8. Security Considerations

When verifying time-stamp tokens it is necessary for the verifier to ensure
that the TSU certificate is trusted and not revoked. This means that the
security is dependent upon the security of the CA that has issued the
TSU certificate for both issuing the certificate and providing accurate
revocation status information for that certificate.

When a time-stamp is verified as valid at a given point of time, this does
not mean that it will necessarily remain valid later on. Every time,
a time-stamp token is verified during the validity period of the TSU
certificate, it must be verified again against the current revocation
status information, since in case of compromise of a TSU private key,
all the time-stamp tokens generated by that TSU become invalid. Annex A
provides guidance about the long term verification of time-stamp tokens.

In applying time-stamping to applications, consideration also needs to be
given to the security of the application. In particular, when applying
time-stamps it is necessary to ensure that the integrity of data is
maintained before the time-stamp is applied. The requester ought to
really make sure that the hash value included in the time-stamp token
matches with the hash of the data.

# Annex A (informative): Long Term Verification of Time-Stamp Tokens

Usually, a time-stamp token becomes unverifiable beyond the end of the
validity period of the certificate from the TSU, because the CA that has
issued the certificate does not warrant any more that it will publish
revocation data, including data about revocations due to key compromises.
However, verification of a time-stamp token might still be performed beyond
the end of the validity period of the certificate from the TSU, if,
at the time of verification, it can be known that:

- the TSU private key has not been compromised at any time up to the
  time that a relying part verifies a time-stamp token;

- the hash algorithms used in the time-stamp token exhibits no
  collisions at the time of verification;

- the signature algorithm and signature key size under which the
  time-stamp token has been signed is still beyond the reach of cryptographic
  attacks at the time of verification.

If these conditions cannot be met, then the validity may be maintained by
applying an additional time-stamp to protect the integrity of the previous one.

The present document does not specify the details of how such protection
may be obtained. For the time being, and until some enhancements are defined
to support these features, the information may be obtained using-out-of
bands means or alternatively in the context of closed environments.
As an example, should a CA guaranty to maintain the revocation status of
TSU certificates after the end of its validity period,
this would fulfill the first requirement.
