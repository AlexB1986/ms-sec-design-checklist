# Microservice application security design assessment checklist 

## Authentication and Access Control

### Authentication Architecture

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that the application uses a single vetted authentication mechanism (IAM service) provided by the platform (e.g., by AWS/GCP/Azure) or 3rd party service originated from trusted source (in case of deployment without PaaS layer) | Microservice application should rely on platform level or matured 3rd-party IAM service, not the custom (self-developed) one. It allows to use verified and maintained IAM solution with solid set of security features that adherence to industry acceptable and/or regulatory compliant authentication |1.2.3|
| Verify that IAM service used in microservice application allows to implement identity federation (OpenID Connect support, sync users from LDAP and Active Directory servers, SAML support) |Most customers want to use existing accounts (e.g., existing in their LDAP) rather that create new one dedicated for application | 1.2.3 |
| Verify that IAM service used in microservice application allows to implement multi-factor authentication | Multi-factor authentication allows to increase security level of application and is usually required by regulation and standards (e.g., NIST). | 1.2.3 |
| Verify that IAM service used in microservice application allows to implement multi-factor authentication | Multi-factor authentication allows to increase security level of application and is usually required by regulation and standards (e.g., NIST) | 1.2.3 |
| Verify that communications between microservices and messages queues (e.g. RabbitMQ, Kafka, NATS) are authenticated and use individual service accounts | Individual service accounts allows to implement logging and monitoring and have more granular access control policy | 1.2.2 |
| Verify that communications between microservices and data storages (DBMS, cache) are authenticated and use individual service accounts | Individual service accounts allows to implement logging and monitoring and have more granular access control policy |1.2.2|
| Verify that authentication is implemented for WebSocket connection | WebSocket protocol doesn't handle authorization or authentication, therefore development team has to implement it | 1.2.2, 13.5 |
| Verify that application decouples external access tokens from its internal representation. Application shall use single data structure (e.g. signed JWT) to represent and propagate external entity identity (ID, tenant ID, roles, permissions, etc.) among application components | In order to implement external access token agnostic and extendable application decouple access tokens issued for external entity from its internal representation. Use single data structure to represent and propagate external entity identity among microservices. Edge-level service has to verify incoming external access token, issue internal entity representation structure and propagate it to downstream services. Using an internal entity representation structure signed (symmetric or asymmetric encryption) by a trusted issuer is recommended pattern adopted by community. Internal entity representation structure should be extensible to enable add more claims that may lead to low latency| - |

### Access Control Architecture

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that application uses a single and well-vetted access control (authorization) mechanism for accessing protected data and resources. All requests must pass through this single mechanism to avoid copy and paste or insecure alternative paths | To achieve scalability it is not advisable to hardcode authorization policy in application source code (decentralized pattern), but use special language to express policy instead. The goal is to externalize/decouple authorization from code, and not just with a gateway/proxy that acts as a checkpoints. Recommended pattern for service-level authorization is “Centralized pattern with embedded PDP” due to its resilience and wide adoption. It is advisable to implement “defense in depth” principle   enforce authorization on:gateways and proxies level at a coarse level of granularity; microservice level using shared authorization library/components to enforce fine-granted decisions; microservice business code level to implement business-specific access control rules | 1.4.4 |
| Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item rather than just their role. Permissions should still be allocated using roles | Role based programming does not allow for data-specific or horizontal access control rules; large codebases with many access control checks can be difficult to audit or verify the overall application access control policy. | 1.4.5|

### Least privilege enforcement

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that communications between microservices and messages queues (e.g. RabbitMQ, Kafka, NATS) are performed with the least necessary privileges, i.e. services accounts has only necessary privileges | This helps to enforce the principle of least privileges at scale | 1.4.6 |
| Verify that communications between microservices and data storages (DBMS, cache) are performed with the least necessary privileges, i.e. services accounts has only necessary privileges | This helps to enforce the principle of least privileges at scale ||
| Verify that authorization is implemented for WebSocket connection | WebSocket protocol doesn't handle authorization or authentication, therefore development team has to implement it | 1.4.6|
| Verify that communications between microservices are performed with the least necessary privileges, i.e. services accounts has only necessary privileges | This helps to enforce the principle of least privileges at scale | 1.4.6 |

### Service-to-service authentication

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that communications between microservices are authenticated via mutual TLS | Mutual TLS is widely used and recommended pattern to implement service-to-service authentication in microservice based application. Usually that pattern is implemented using side-car service proxy (service mesh). Alternative pattern is to use TLS and JWT to authenticate service-to-service communication. It also should be noted that depending on threat model security architect may not use encryption (just use HTTP) for inner-service communication | 1.9.2 |
| Verify that consistent names (identities) for microservices are used and carried in TLS certificate “subject name” or “subject alternative name” fields or in JWT “client ID” or similar field | The identity of all instances of a microservice should be consistent and unique—consistent in that a service should have the same name regardless of where it is running and unique in that across the entire system, the service’s name corresponds only to that service. Consistent names (identities) for services are required so that the system policy is manageable. Identity can either be a server identity (also known as a host or domain) or a service identity (usually service account ID) | 1.2.2 |
| Verify that the lifetime of a microservice’s identity certificate or JWT  is short as is manageable within the infrastructure, preferably on the order of hours | This helps limit attacks since an attacker can only use a credential to impersonate a service until that credential expires, and successfully re-stealing a credential increases the difficulty for an attacker| - |
| Verify that reference architecture/microservice blueprint/libraries that implement JWT verification exists and that all microservices use that pattern (if JWT via TLS is used) | Although in case of polyglot architecture developers may decide which JWT library use for their portion of microservice independently, their choice may be vulnerable and not matured. It is advisable to define the set of JWT libraries allowed to use by development teams | 1.9.2 |
| Verify that for critical operation microservices make online JWT verification, i.e. make request to security token service to check provided JWT (if JWT via TLS is used) | |-|

### Tenant isolation

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that tenant isolation model that is resistant to cross-tenant access attacks is defined and implemented | These models fall into one of three categories: silo, bridge, and pool | - |
| Verify that tenant isolation model for every storage type (DBMS, messages queues, cache, S3, etc.) is  defined and implemented | Tenant isolation strategy has to be applied not only to DBMS, but to all types of storages in SaaS application: messages queues, caches, S3 | - |

## Errors, Logging and Auditing Architecture

### Logging architecture

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that the application uses a single common logging architecture pattern (platform-based or custom solution), verify that reference architecture/microservice blueprint/library/components exists | It is advisable to rely on platform level logging subsystem (e.g., Cloud Logging in GCP, Amazon CloudWatch in AWS) | 1.7.2|
| When custom logging architecture pattern (not offered by the PaaS) used, verify that microservices do not send log messages directly to the central logging subsystem using network communication, but write its log message to a local log file | This allows to mitigate the threat of data loss due to logging service failure due to attack or in case of its flooding by legitimate microservice: in case of logging service outage, microservice will still write log messages to the local file (without data loss), after logging service recovery logs will be available to shipping | 1.7.2|
| When custom logging architecture pattern (not offered by the platform) used, verify that there is a dedicated component (logging agent) decoupled from the microservice. The logging agent collects log data on the microservice (read local log file) and send it to the central logging subsystem | Due to possible network latency issues, the logging agent shall be deployed on the same host (virtual or physical machine) with the microservice: this allows mitigating the threat of data loss due to logging service failure due to attack or in case of its flooding by legitimate microservice | 1.7.2 |
| When custom logging architecture pattern (not offered by the platform) used, verify that there is a message broker to implement the asynchronous connection between the logging agent and central logging service | This allows to mitigate the threat of data loss due to logging service failure in case of its flooding by legitimate microservice; in case of logging service outage, microservice will still write log messages to the local file (without data loss) after logging service recovery logs will be available to shipping | 1.7.2|
| Verify that logging agent and message broker use mutual authentication (e.g., based on TLS) to encrypt all transmitted data (log messages) and authenticate themselves | This allows mitigating threats: microservice spoofing, logging/transport system spoofing, network traffic injection, sniffing network traffic | 1.7.1 |

### Logging format

| Check item | Comments | OWASP ASVS |
| :--- | :--- | :---:|
| Verify that a common logging format and structured logs format (e.g., JSON, CSV) are used across the SaaS application | Common logging format allows to aggregate logs and detect threats based on log analysis | 1.7.2 |
| Verify that logging agent appends log messages with context data, e.g., platform context (hostname, container name), runtime context (class name, filename) | This allows to aggregate log records more accurately, apply threat detection algorithms | 1.7.2 |
| Verify that microservices generates a correlation ID that uniquely identifies every call chain and logging agent includes a correlation ID in every log message | This helps group log messages to investigate them | 1.7.2 |
