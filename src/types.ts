/** The portable verify package, as the Platform export writes it. */
export interface TrustableVerifyPackage {
  schema_version: number;
  trustable_said?: string;
  acdc_said: string;
  issuer_aid: string;
  registry_id?: string;
  cesr?: string;
  acdc?: Record<string, unknown>;
  kel?: string;
  tel?: unknown;
  registry_tel?: unknown;
  schema?: unknown;
  integrity?: { said_checkable?: boolean; reason?: string };
  content_redacted?: { reason?: string; retention_policy?: string };
  credential_status?: { status?: string; said?: string; as_of?: string };
  trustable_status?: { current_state?: string };
  signature_policy?: unknown;
  signatures?: unknown;
  packaged_at?: string;
  [key: string]: unknown;
}

export type CheckStatus = "passed" | "failed" | "degraded";

export interface TrustReportStep {
  status: CheckStatus;
  passed: boolean;
  message: string;
  details: string;
  timestamp: string;
}

export interface TrustReportSteps {
  structureValidation: TrustReportStep;
  saidIntegrity: TrustReportStep;
  schemaCompliance: TrustReportStep;
  cryptographicVerification: TrustReportStep;
  kelDiscovery: TrustReportStep;
  telValidation: TrustReportStep;
  revocationStatus: TrustReportStep;
}

export interface TrustReport {
  steps: TrustReportSteps;
  status: "verified" | "invalid" | "revoked" | "suspended";
  isValid: boolean;
  trustScore: "high" | "medium" | "limited" | "failed";
  verifiedAt: string;
  credentialSaid: string;
  issuerAid: string;
}

export interface OfflineVerificationResult {
  isValid: boolean;
  status: TrustReport["status"];
  credentialSaid: string;
  issuerAid: string;
  verifiedAt: string;
  trustScore: TrustReport["trustScore"];
  trustReport: TrustReport;
  /**
   * Whether the issuer's authorship was proven, as opposed to merely not
   * contradicted. Separate from `isValid` so a caller can see WHY a
   * well-formed package is not being called verified.
   */
  authenticity: { established: boolean; reason?: string };
  /** Always `offline` here. The field exists so both paths report alike. */
  verification_mode: "offline";
  /**
   * The moment the package describes. An offline answer is about that moment
   * and no other — never `now`, which would date a snapshot to the present.
   */
  as_of: string | null;
  package_schema_version: number;
}
