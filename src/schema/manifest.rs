use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

#[doc = "Root governance manifest for an Elaine-audited repository (`elaine.yaml`)."]
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ElaineManifest {
    #[doc = "Explicit schema version for manifest compatibility (must be 1)."]
    #[schemars(schema_with = "schema_version_schema")]
    pub schema_version: u32,

    pub name: String,

    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ProjectType")]
    pub project_type: Option<ProjectType>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "LifecycleType")]
    pub lifecycle: Option<LifecycleType>,

    #[doc = "Operational service tier dictating on-call priority and internal incident response targets."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ServiceTier")]
    pub tier: Option<ServiceTier>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Vec<AuthType>")]
    pub authentication: Option<Vec<AuthType>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Vec<Sensitivity>")]
    pub sensitivity: Option<Vec<Sensitivity>>,

    #[doc = "Regulatory compliance and resilience framework mappings."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ComplianceManifest")]
    pub compliance: Option<ComplianceManifest>,

    #[doc = "Internal project stewards and domain experts to contact for reference and context."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stewards: Option<Vec<String>>,

    #[doc = "Company or legal entity that commissioned or paid for the project."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commissioner: Option<String>,

    #[doc = "Channel partner, agency, or system integrator brokering the project relationship."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,

    #[doc = "Environment-specific deployment configurations."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environments: Option<Vec<EnvironmentManifest>>,
}

#[doc = "Primary architectural role of the project."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum ProjectType {
    #[doc = "Shared code dependency imported by other projects."]
    Library,
    #[doc = "Long-running server, API, or backend daemon."]
    Service,
    #[doc = "CLI utility or internal developer tool."]
    Tool,
    #[doc = "Infrastructure-as-Code or IAC libraries (e.g., Terraform, OpenTofu, Pulumi, or Ansible blueprints)."]
    Infrastructure,
    #[doc = "Documentation, slides, courses."]
    Documentation,
    #[doc = "Personal projects, studies, and learning experiments with no production intent."]
    Playground,
}

#[doc = "Operational maintenance status of the repository."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum LifecycleType {
    #[doc = "Actively developed and supported in production."]
    Active,
    #[doc = "Scheduled for decommissioning; do not add new dependencies."]
    Deprecated,
    #[doc = "Decommissioned, no longer actively developed, deployed or running."]
    EndOfLife,
    #[doc = "In production but receiving only critical bug/security fixes."]
    Maintenance,
    #[doc = "Experimental proof-of-concept; no production SLA."]
    Prototype,
    #[doc = "In production and running, but no maintenance contract in place."]
    Unmaintained,
}

#[doc = "Operational service tier dictating on-call priority and internal incident response targets."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum ServiceTier {
    #[doc = "Tier 1: Critical production path (24/7 on-call, immediate response SLO)."]
    Tier1,
    #[doc = "Tier 2: Core supporting functionality (business hours support, rapid degradation fallback)."]
    Tier2,
    #[doc = "Tier 3: Internal developer tools, async batch jobs, or non-critical support utilities."]
    Tier3,
    #[doc = "Tier 4: Experimental prototypes, sandbox playgrounds, or best-effort utilities."]
    Tier4,
}

#[doc = "Primary authentication mechanism for ingress requests."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum AuthType {
    #[doc = "Identity provider abstraction."]
    Idp,
    #[doc = "OpenID Connect (OIDC) identity authentication layer."]
    Oidc,
    #[doc = "Generic OAuth 2.0 framework."]
    Oauth2,
    #[doc = "Generic SAML 2.0 Web SSO."]
    Saml,
    #[doc = "API Key header or query parameter validation."]
    ApiKey,
    #[doc = "Stateless JSON Web Token (JWT) signature validation."]
    Jwt,
    #[doc = "Mutual TLS client certificate authentication."]
    Mtls,
    #[doc = "HMAC request signature validation (e.g., webhooks)."]
    Hmac,
    #[doc = "Stateful cookie or HTTP session authentication."]
    Session,
    #[doc = "Custom bearer token or generic token authentication."]
    Token,
    #[doc = "HTTP Basic authentication (legacy/internal)."]
    Basic,
    #[doc = "Passkey authentication."]
    Passkey,
    #[doc = "LDAP authentication."]
    Ldap,
    #[doc = "Custom HTML form authentication."]
    Form,
    #[doc = "Explicitly public endpoint accepting unauthenticated requests (e.g., public API or landing page)."]
    Unauthenticated,
    #[doc = "Authentication is not applicable (e.g., offline CLI utility, library, or background job)."]
    NotApplicable,
}

#[doc = "Sensitive data classifications handled by the service."]
#[doc = ""]
#[doc = "### Data Classification Hierarchy"]
#[doc = "* **Public** → **Internal** → **Confidential** → **Restricted**"]
#[doc = ""]
#[doc = "### Regulatory Standards Covered"]
#[doc = "* **GDPR / CCPA / BIPA:** `Pii`, `Spi`, `Biometric`"]
#[doc = "* **PCI-DSS:** `Pci`"]
#[doc = "* **SOX:** `Financial`"]
#[doc = "* **HIPAA:** `Phi`"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum Sensitivity {
    #[doc = "Non-sensitive data safe for public distribution."]
    Public,
    #[doc = "Standard internal business data."]
    Internal,
    #[doc = "Restricted company intellectual property or business trade secrets."]
    Confidential,
    #[doc = "Maximum security assets requiring strict isolation (e.g., root credentials, master keys)."]
    Restricted,
    #[doc = "Personally Identifiable Information (names, emails, addresses)."]
    Pii,
    #[doc = "Sensitive PII / Special Category Data (genetics, political/religious beliefs under GDPR Art. 9)."]
    Spi,
    #[doc = "Biometric identification data (fingerprints, facial recognition, voice signatures)."]
    Biometric,
    #[doc = "Payment Card Industry data (credit cards, billing details, PANs)."]
    Pci,
    #[doc = "Non-PCI financial records (SOX audit trails, payroll, company accounting, bank accounts)."]
    Financial,
    #[doc = "Protected Health Information (medical records, insurance claims, health data)."]
    Phi,
}

#[doc = "Regulatory compliance and cybersecurity resilience specifications."]
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceManifest {
    #[doc = "DORA (Digital Operational Resilience Act) criticality tag."]
    #[doc = "Applicable if your project serves the EU financial sector or acts as an ICT third-party provider to financial entities."]
    pub dora: DoraCriticality,

    #[doc = "EU Cyber Resilience Act (CRA) product classification tier."]
    #[doc = "Applicable if your software product contains digital elements and is sold or distributed within the EU."]
    pub cra: CraClass,

    #[doc = "EU NIS2 Directive criticality classification."]
    #[doc = "Applicable to non-financial critical and important infrastructure operating in the EU (e.g., energy, health, SaaS, MSPs)."]
    pub nis2: Nis2Category,

    #[doc = "EU AI Act risk classification tier."]
    #[doc = "Applicable to systems integrating AI/ML models, LLMs, or automated inference."]
    pub ai_act: AiActClass,

    #[doc = "GDPR data protection role."]
    #[doc = "Applicable to any project that processes, stores, or transmits EU/EEA personal data."]
    pub gdpr: GdprRole,

    #[doc = "Whether personal data is processed or stored strictly within the EU/EEA."]
    pub data_residency: DataResidency,

    #[doc = "Italian Garante Privacy 'Amministratore di Sistema' (AdS) compliance block."]
    #[doc = "Applicable to projects falling under the Italian Provvedimento Garante AdS for tracking privileged IT and database administrators."]
    pub ads: AdsResponsibility,
}

#[doc = "EU NIS2 Directive classification tier for cybersecurity resilience."]
#[doc = "Applicable to non-financial critical and important infrastructure operating in the EU (e.g., energy, health, SaaS, MSPs)."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum Nis2Category {
    #[doc = "Essential Entity (Soggetti Essenziali): Energy, transport, banking, health, digital infrastructure."]
    EssentialEntity,
    #[doc = "Important Entity (Soggetti Importanti): Postal, waste, chemicals, food, digital providers (SaaS/marketplaces)."]
    ImportantEntity,
    #[doc = "Not in scope of NIS2 requirements."]
    OutOfScope,
    #[doc = "Applicability has not yet been assessed."]
    PendingAssessment,
}

#[doc = "EU AI Act risk classification tier."]
#[doc = "Applicable to systems integrating AI/ML models, LLMs, or automated inference."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum AiActClass {
    #[doc = "High-Risk AI System (biometrics, critical infrastructure, employment, credit scoring)."]
    HighRisk,
    #[doc = "General Purpose AI (GPAI) model or foundation model integration."]
    GeneralPurposeAi,
    #[doc = "Limited Risk AI System (requires transparency disclosures, e.g., chatbots/AI assistants)."]
    LimitedRisk,
    #[doc = "Minimal or no risk AI system."]
    MinimalRisk,
    #[doc = "Not in scope of AI Act requirements."]
    OutOfScope,
    #[doc = "Applicability has not yet been assessed."]
    PendingAssessment,
}

#[doc = "Geographic data storage and processing boundary for compliance."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum DataResidency {
    #[doc = "Data is stored and processed strictly within European Union member states."]
    Eu,
    #[doc = "Data is stored and processed within the European Economic Area (EU + Iceland, Liechtenstein, Norway)."]
    Eea,
    #[doc = "Data is stored or processed in the US."]
    Us,
    #[doc = "Data is stored or processed globally across international regions."]
    Global,
    #[doc = "No data is stored."]
    NotApplicable,
    #[doc = "Applicability has not yet been assessed."]
    PendingAssessment,
}

#[doc = "Legal processing role under GDPR (Art. 4)."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum GdprRole {
    #[doc = "Data Controller (Titolare del trattamento) - determines purposes and means of processing."]
    Controller,
    #[doc = "Data Processor (Responsabile del trattamento) - processes data on behalf of a Controller."]
    Processor,
    #[doc = "Sub-processor (Sub-responsabile) - third-party processor engaged by a Processor."]
    SubProcessor,
    #[doc = "No personal data processed."]
    None,
    #[doc = "Not in scope of GDPR requirements."]
    OutOfScope,
    #[doc = "Applicability has not yet been assessed."]
    PendingAssessment,
}

#[doc = "DORA (Digital Operational Resilience Act) operational criticality tag."]
#[doc = "Applicable if your project serves the EU financial sector or acts as an ICT third-party provider to financial entities."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum DoraCriticality {
    #[doc = "Supports a Critical or Important Function (CIF) subject to strict RTO/RPO SLAs."]
    CifSupported,
    #[doc = "Non-critical ICT supporting service or internal developer utility."]
    NonCritical,
    #[doc = "Not in scope of DORA requirements."]
    OutOfScope,
    #[doc = "Applicability has not yet been assessed."]
    PendingAssessment,
}

#[doc = "EU Cyber Resilience Act (CRA) product classification tier for cybersecurity compliance."]
#[doc = "Applicable if your software product contains digital elements and is sold or distributed within the EU."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum CraClass {
    #[doc = "Default category: Standard software product with digital elements."]
    Default,
    #[doc = "Important Class I: Identity management, password managers, VPNs, network monitors."]
    ImportantClass1,
    #[doc = "Important Class II: Hypervisors, container runtimes, firewalls, IDS/IPS."]
    ImportantClass2,
    #[doc = "Critical: Smartcards, hardware security modules, and core cryptographic hardware/software."]
    Critical,
    #[doc = "Not in scope of CRA requirements."]
    OutOfScope,
    #[doc = "Applicability has not yet been assessed."]
    PendingAssessment,
}

#[doc = "System Administrator (AdS) operational responsibility boundary."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum AdsResponsibility {
    #[doc = "Our organization directly manages the system/infrastructure as AdS."]
    Internal,
    #[doc = "An external Managed Service Provider (MSP) / Vendor holds AdS duties."]
    ExternalProcessor,
    #[doc = "The client / customer holds AdS responsibility for their own environment."]
    ClientManaged,
    #[doc = "Pending formal designation letters ('Lettera di Nomina') to be executed."]
    PendingNomination,
    #[doc = "Status has not yet been assessed."]
    PendingAssessment,
    #[doc = "Not in scope of ADS requirements."]
    OutOfScope,
}

#[doc = "Environment-specific deployment configuration."]
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentManifest {
    #[doc = "Target deployment environment."]
    #[schemars(schema_with = "identifier_schema")]
    pub name: String,

    #[doc = "Target deployment environment type."]
    #[serde(rename = "type")]
    pub environment_type: EnvironmentType,

    #[doc = "Underlying deployment platform (cloud, on-premises, edge)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "PlatformType")]
    pub platform: Option<PlatformType>,

    #[doc = "Architectural stack layers owned and maintained directly by our organization."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Vec<StackLayer>")]
    pub ownership: Option<Vec<StackLayer>>,

    #[doc = "Network ingress reachability for this specific environment."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ExposureType")]
    pub ingress: Option<ExposureType>,

    #[doc = "Network management reachability for this specific environment."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "ExposureType")]
    pub management: Option<ExposureType>,

    #[doc = "DNS management and ownership origin."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "DnsManagement")]
    pub dns: Option<DnsManagement>,

    #[doc = "List of domain names assigned to this environment."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,

    #[doc = "TLS certificate provisioning and renewal mechanism."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "CertManagement")]
    pub certificates: Option<CertManagement>,
}

#[doc = "Supported deployment environment types."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum EnvironmentType {
    #[doc = "Developer workstation running the project locally."]
    Local,
    #[doc = "Shared development environment for ongoing feature work."]
    Development,
    #[doc = "Ephemeral per-branch or per-pull-request preview deployment."]
    Preview,
    #[doc = "Automated testing environment (unit/integration test runs)."]
    Testing,
    #[doc = "Dedicated QA environment for manual quality assurance."]
    Qa,
    #[doc = "User acceptance testing environment validated by end users/customers."]
    Uat,
    #[doc = "Isolated playground for experiments without production data."]
    Sandbox,
    #[doc = "Pre-production environment mirroring production for final validation."]
    PreProduction,
    #[doc = "Staging area replicating production for release rehearsal."]
    Staging,
    #[doc = "Customer or sales demonstration environment."]
    Demo,
    #[doc = "Performance and load testing environment."]
    Performance,
    #[doc = "Shadow environment processing a mirror of live traffic without user-facing effects."]
    Shadow,
    #[doc = "Live production environment serving real users."]
    Production,
    #[doc = "Disaster recovery standby environment for failover."]
    DisasterRecovery,
}

#[doc = "Underlying deployment platform or infrastructure substrate."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum PlatformType {
    #[doc = "Generic cloud provider (unspecified)."]
    Cloud,
    #[doc = "Amazon Web Services (AWS)."]
    CloudAws,
    #[doc = "Microsoft Azure."]
    CloudAzure,
    #[doc = "Google Cloud Platform (GCP)."]
    CloudGcp,
    #[doc = "Hetzner Cloud."]
    CloudHetzner,
    #[doc = "Owned/rented datacenter operated by our organization."]
    Datacenter,
    #[doc = "On-premises infrastructure hosted at the customer's site."]
    OnPremises,
    #[doc = "Colocation facility housing our own hardware."]
    Colocation,
    #[doc = "Hybrid mix of cloud and on-premises/datacenter infrastructure."]
    Hybrid,
    #[doc = "Edge computing nodes close to end users."]
    Edge,
    #[doc = "Internal development network (not customer reachable)."]
    DevNetwork,
}

#[doc = "Architectural stack layer managed directly by our organization."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum StackLayer {
    #[doc = "Infrastructure layer (compute, networking, storage provisioning)."]
    Infrastructure,
    #[doc = "Operating system layer (OS installation, patching, base configuration)."]
    OperatingSystem,
    #[doc = "Middleware/services layer (databases, message brokers, runtimes)."]
    Services,
    #[doc = "Application layer (deployed application code and business logic)."]
    Applications,
}

#[doc = "Network ingress reachability for the project."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum ExposureType {
    #[doc = "Reachable only from the local machine or internal network."]
    Local,
    #[doc = "Reachable only through a VPN connection."]
    RestrictedVpn,
    #[doc = "Reachable only from an allowlisted set of IP addresses."]
    RestrictedIp,
    #[doc = "Reachability restricted using geo ip location."]
    RestrictedGeoIp,
    #[doc = "Reachable only through a Privileged Access Management (PAM) bastion."]
    RestrictedPam,
    #[doc = "Publicly reachable from the Internet."]
    Internet,
    #[doc = "No network reachability (air-gapped or disabled)."]
    None,
}

#[doc = "Domain management and ownership origin."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum DnsManagement {
    #[doc = "DNS zones and records managed directly by our organization."]
    Managed,
    #[doc = "DNS zones and records managed by an external party."]
    External,
}

#[doc = "TLS certificate provisioning and renewal mechanism."]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum CertManagement {
    #[doc = "Automatically provisioned and renewed via ACME DNS-01 challenge."]
    ManagedAcmeDns01,
    #[doc = "Automatically provisioned and renewed via ACME HTTP-01 challenge."]
    ManagedAcmeHttp01,
    #[doc = "Automatically renewed by a managed tool (non-ACME)."]
    ManagedAutoRenew,
    #[doc = "Manually provisioned and renewed by our organization."]
    ManagedManual,
    #[doc = "Certificate supplied by a third party (e.g., customer-provided)."]
    ThirdPartyProvided,
    #[doc = "Certificate lifecycle fully managed by a third party."]
    ThirdPartyManaged,
    #[doc = "No TLS certificate in use (plain HTTP or no network endpoint)."]
    NotApplicable,
}

fn schema_version_schema(_generator: &mut SchemaGenerator) -> Schema {
    let schema_val = serde_json::json!({
        "type": "integer",
        "const": 1,
        "description": "Explicit schema version for manifest compatibility (must be 1)."
    });
    serde_json::from_value(schema_val).expect("valid schema")
}

fn identifier_schema(_generator: &mut SchemaGenerator) -> Schema {
    let schema_val = serde_json::json!({
        "type": "string",
        "pattern": "^[A-Za-z0-9-_]+$",
        "description": "A valid identifier."
    });
    serde_json::from_value(schema_val).expect("valid schema")
}
