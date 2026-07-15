# Implementation of Secure Software Development Life Cycle (SSDLC) in a Hybrid Cryptographic Gate-Log System Utilizing ECC P-256 and Ascon-128

**Abstract**—This paper presents a rigorous analysis of the "Guard App," a centralized gate-log system engineered for the Politeknik Siber dan Sandi Negara (Poltek SSN), meticulously evaluated through the Secure Software Development Life Cycle (SSDLC) framework. Prioritizing the "Security-by-Design" paradigm, the architecture operationalizes a Hybrid Cryptography model that synergizes Elliptic Curve Cryptography (ECC P-256) for resilient key exchange with Ascon-128 for lightweight Authenticated Encryption with Associated Data (AEAD). The integration of National Institute of Standards and Technology (NIST) lightweight cryptographic standards within a modern micro-framework directly addresses the critical necessity of mitigating Man-In-The-Middle (MITM) attacks and payload tampering, while preserving the computational efficiency required by resource-constrained client environments. Through a systematic mapping of SSDLC phases—spanning Secure Requirements Analysis to Security Verification—this research provides a concrete Proof of Concept demonstrating the pragmatic deployment of advanced cryptographic primitives in physical security infrastructures.

**Index Terms**—Secure Software Development Life Cycle (SSDLC), Hybrid Cryptography, Elliptic Curve Cryptography (ECC), Ascon-128, Authenticated Encryption, Web Security.

---

## I. INTRODUCTION
The governance of personnel movement, specifically the monitoring of ingress and egress operations in institutions with uncompromising security protocols such as Poltek SSN, represents a foundational element of organizational security. Traditional manual logging procedures and elementary digital implementations are intrinsically vulnerable due to the conspicuous absence of cryptographic safeguards. Such systemic inadequacies expose critical institutional data to an array of sophisticated threats, notably network eavesdropping, unauthorized data manipulation, and the compromise of Personally Identifiable Information (PII).

To remediate these structural vulnerabilities, the imperative integration of the Secure Software Development Life Cycle (SSDLC) methodology is required. The paradigm of "Security-by-Design," which embeds security controls into every developmental phase, is essential for cultivating resilience against modern cyber adversaries. This paper comprehensively examines the "Guard App," a centralized application designed to guarantee the confidentiality, integrity, and non-repudiation of operational data. By analyzing the system through the SSDLC methodology, this study elucidates the operationalization of NIST-standardized lightweight cryptography (Ascon-128) in conjunction with ECC P-256 within a lightweight micro-framework, thereby proposing a highly secure architectural baseline for physical access management.

## II. SECURE REQUIREMENTS ANALYSIS AND THREAT MODELING
The foundational phase of the SSDLC demands a stringent Secure Requirements Analysis, predicated on an accurate assessment of the threat landscape. The operational environment of the Guard App is characterized by potential adversarial actors seeking to subvert the integrity and privacy of the log data.

The primary vectors identified in the threat model encompass:
1. **Man-In-The-Middle (MITM) Attacks:** The unauthorized interception of network traffic between the client interface (browser) and the backend server, with the intent to eavesdrop on or forge transit logs.
2. **Payload Manipulation:** The malicious alteration of telemetry data during transmission. In conventional systems, a single bit modification can precipitate catastrophic logical state failures.
3. **Resource Constraints:** Client terminals deployed at security outposts frequently exhibit limited computational capacity, thereby precluding the application of computationally intensive cryptographic standards (e.g., RSA-3072) without inducing significant latency.

To neutralize these threats, the Secure Requirements mandate the deployment of robust End-to-End Encryption (E2EE) utilizing lightweight algorithms. The cryptographic architecture must seamlessly assure confidentiality and integrity without compromising the operational responsiveness of the browser client.

## III. SSDLC METHODOLOGY: SECURE DESIGN
In the Secure Design phase, architectural blueprints are formulated to satisfy the predefined threat model. The Guard App implements a Hybrid Cryptography architecture, strategically amalgamating the secure key distribution capabilities of asymmetric cryptography with the high-throughput processing of symmetric encryption.

### A. Cryptographic Primitives
1. **Elliptic Curve Cryptography (ECC P-256):** Selected for orchestrating the Elliptic Curve Diffie-Hellman (ECDH) key exchange, ECC furnishes a superior security margin utilizing a minimal key size (256-bit). This guarantees an exceptionally resource-efficient and bandwidth-friendly operation compared to traditional asymmetric algorithms.
2. **HKDF-SHA256:** This HMAC-based Key Derivation Function is strictly employed to derive a robust 16-byte Key Encryption Key (KEK) from the ECDH shared secret, ensuring cryptographic resilience and uniform distribution within the key space.
3. **Ascon-128 (Lightweight AEAD):** Designated as the NIST standard for lightweight cryptography, Ascon-128 executes a dual mandate within the system: cryptographic wrapping of the symmetric key and the direct encryption of the JSON payload. Its Authenticated Encryption with Associated Data (AEAD) characteristics natively enforce both confidentiality and stringent integrity.

### B. Cryptographic Workflow
The secure design dictates the following protocol sequence:
1. The server provisions a static ECC P-256 key pair, disseminating its Public Key to the client browser.
2. Upon user submission, the client generates an ephemeral ECC key pair and locally computes a Shared Secret via ECDH, leveraging the server's Public Key.
3. The client subsequently derives the KEK utilizing the HKDF-SHA256 algorithm.
4. A transient 16-byte Ascon Symmetric Key is instantiated by the client, which is then cryptographically wrapped by the KEK using Ascon-128.
5. The payload containing the actual cadet log data is encrypted via the Ascon Symmetric Key.
6. A composite data packet—comprising the Client Ephemeral Public Key, the Wrapped Key, and the Ciphertext Data—is transmitted to the server.
7. Upon receipt, the server reconstructs the Shared Secret and KEK by processing the Client Ephemeral Public Key against its static Private Key.
8. Ultimately, the server unwraps the Ascon Symmetric Key and decrypts the payload for secure, persistent storage.

## IV. SSDLC METHODOLOGY: SECURE IMPLEMENTATION
The Secure Implementation phase represents the translation of the cryptographic blueprint into executable software. The Guard App architecture utilizes FastAPI (Python) for the backend micro-framework and Vanilla JavaScript for the frontend, heavily capitalizing on the native Web Crypto API. This approach ensures that sophisticated cryptographic operations are executed efficiently and transparently within the client's environment.

Prominent secure implementation characteristics include:
- **Client-Side Cryptographic Execution:** By executing Ascon-128 and ECC operations natively within the browser via the Web Crypto API, the application guarantees that unencrypted plaintext never traverses the network layer, comprehensively fulfilling the E2EE mandate.
- **Dual-Mode Entry and Data Synchronization:** To augment operational efficacy, the interface supports both individual and bulk entry paradigms. Furthermore, an automated spreadsheet synchronization module systematically populates the operational database securely, mitigating vulnerabilities associated with manual data entry errors.
- **Audit Trail and Non-Repudiation:** To enforce strict non-repudiation, every critical system operation—such as logging a departure or mass-clearing active logs—is immutably recorded in an isolated audit database. These records are exclusively stamped with server-side chronometry and the respective Guard ID, ensuring absolute traceability.

## V. SECURITY VERIFICATION AND AUDITING
The culmination of the implemented SSDLC is the Security Verification phase. The Guard App inherently integrates verification mechanisms at the fundamental algorithmic tier. The AEAD properties of Ascon-128 furnish an automated, mathematically rigorous integrity validation protocol. During the decryption sequence, the Ascon algorithm continuously evaluates the cryptographic authentication tag. Any unauthorized manipulation—even down to a single-bit alteration—induces an immediate cryptographic failure, compelling the system to unconditionally reject the tampered payload.

Moreover, the robust Audit Trail system guarantees the continuous verification of operational integrity. By restricting access logs to purely server-side timestamps, the architecture effectively neutralizes threat vectors attempting client-side temporal manipulation, thus delivering an authoritative and auditable ledger of all institutional movements.

## VI. CONCLUSION AND FUTURE WORKS
This paper substantiates the successful deployment of the SSDLC methodology in the engineering of the "Guard App," a high-assurance gate-log system. By integrating a Hybrid Cryptography framework employing ECC P-256 and Ascon-128, the application decisively mitigates critical cyber vulnerabilities, including MITM attacks and payload tampering. 

Academically, this project stands as a definitive Proof of Concept, verifying the practical operationalization of NIST's lightweight cryptography within a modern micro-framework architecture. It empirically demonstrates that military-grade cryptographic protocols can be flawlessly deployed to resolve real-world physical security demands without overburdening resource-constrained clients. Future research trajectories may investigate the incorporation of biometric authentication modalities to further fortify the primary access vectors, as well as the transition toward Post-Quantum Cryptography (PQC) algorithms to guarantee long-term system survivability against advanced computational adversaries.
