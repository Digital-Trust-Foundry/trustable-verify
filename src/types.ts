import type { PackagedApproval } from "./approvals.js";

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
  /**
   * The approval credentials answering the signature policy this credential
   * names, each with the evidence that proves it: the approving signer's key
   * event log and the registry history that anchors the approval's issuance.
   *
   * Absent from packages written before approvals travelled, which is why a
   * credential that required a round and carries none of them reports the round
   * as unproven rather than absent.
   */
  approvals?: PackagedApproval[];
  packaged_at?: string;
  [key: string]: unknown;
}

export type CheckStatus = "passed" | "skipped" | "degraded" | "failed";

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
  /**
   * Whether the approvals the credential itself required can be shown to have
   * happened. Absent from the hosted report before the policy was bound into
   * the credential, so consumers must treat it as optional.
   */
  approvalCompletion?: TrustReportStep;
  kelDiscovery: TrustReportStep;
  telValidation: TrustReportStep;
  revocationStatus: TrustReportStep;
}

export type TrustBand = "high" | "medium" | "limited" | "failed";

export interface TrustCheckCounts {
  passed: number;
  skipped: number;
  degraded: number;
  failed: number;
  total: number;
  runnable: number;
}

export interface TrustScore {
  /**
   * 0-100. The sum of weights for `passed` checks, bounded by the band —
   * `limited` caps at 60, `failed` is always 0.
   */
  score: number;
  /**
   * Passed checks over checks that actually ran, so a skipped check neither
   * helps nor hurts. 0-1.
   */
  confidence: number;
  band: TrustBand;
  counts: TrustCheckCounts;
}

export interface TrustReport {
  steps: TrustReportSteps;
  status: "verified" | "invalid" | "revoked" | "suspended";
  isValid: boolean;
  trustScore: TrustScore;
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
  trustScore: TrustScore;
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
