export interface DriftHistory {
  scan_id: string;
  target: string;
  timestamp: string;
  total_artefacts: number;
  vulnerable_artefacts_count: number;
  pqc_artefacts_count: number;
  pqc_adoption_percentage: number;
  average_migration_priority: number;
  total_assets: number;
  critical_risks: number;
  high_risks: number;
}

export interface ScanDriftResponse {
  target: string;
  scans_tracked: number;
  history: DriftHistory[];
  delta: {
    vulnerable_artefacts_delta: number;
    pqc_adoption_percentage_delta: number;
    average_migration_priority_delta: number;
    critical_risks_delta: number;
    posture_improved: boolean;
  } | null;
}

// Extend Asset with HNDL fields
export interface Asset {
  id: string;
  scan_id: string;
  name: string;
  asset_type: string;
  algorithm_name: string | null;
  key_size: number | null;
  purpose: string;
  component: string;
  location: string;
  confidence: number;
  business_asset: string | null;
  risk: RiskAssessment | null;
  mosca: MoscaAssessment | null;
  recommendation: Recommendation | null;
  hndl_exposed?: boolean;
  hndl_reason?: string;
}

  id: string;
  target: string;
  target_type: string;
  scanners_requested: string[];
  status: "pending" | "running" | "completed" | "failed";
  start_time: string | null;
  end_time: string | null;
  files_scanned: number;
  artefacts_found: number;
  errors: { scanner: string; level: string; message: string; file: string }[];
  created_at: string;
}

export interface RiskAssessment {
  id: string;
  asset_id: string;
  score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  factors: { name: string; impact: number; detail?: string }[];
}

export interface MoscaAssessment {
  id: string;
  asset_id: string;
  x_data_lifetime_years: number;
  y_migration_time_years: number;
  z_threat_horizon_years: number;
  x_plus_y: number;
  exceeds_horizon: boolean;
  result: "URGENT MIGRATION" | "PLAN MIGRATION" | "MONITOR" | "LOW PRIORITY";
}

export interface Recommendation {
  id: string;
  asset_id: string;
  current_algorithm: string;
  category: string;
  recommended_algorithm: string;
  recommended_type: string;
  hybrid_option: string;
  reason: string;
  compatibility: string;
  migration_complexity: string;
  priority: string;
  confidence: number;
}

export interface Asset {
  id: string;
  scan_id: string;
  name: string;
  asset_type: string;
  algorithm_name: string | null;
  key_size: number | null;
  purpose: string;
  component: string;
  location: string;
  confidence: number;
  business_asset: string | null;
  risk: RiskAssessment | null;
  mosca: MoscaAssessment | null;
  recommendation: Recommendation | null;
}

export interface MigrationPlan {
  id: string;
  asset_id: string;
  asset_name: string;
  algorithm: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  rationale: string;
  blockers: string[];
  replacement: string;
  affected_dependencies: string[];
  risk_before: number | null;
  risk_after_estimate: string;
}

export interface Certificate {
  id: string;
  file: string;
  subject: string;
  issuer: string;
  serial_number: string;
  valid_from: string | null;
  valid_until: string | null;
  expired: boolean;
  days_remaining: number | null;
  public_key_algorithm: string;
  key_size: number | null;
  signature_algorithm: string;
  san: string[];
  weak_key: boolean;
  weak_signature: boolean;
  parse_error: string | null;
}

export interface Library {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  source_file: string;
  crypto_capable: boolean;
  known_algorithms: string[];
  confidence: number;
}

export interface DashboardData {
  total_crypto_assets: number;
  quantum_vulnerable_assets: number;
  critical_risks: number;
  high_risks: number;
  certificates_found: number;
  crypto_libraries_found: number;
  applications_scanned: number;
  scans_run: number;
  risk_distribution: Record<string, number>;
  algorithm_distribution: Record<string, number>;
  asset_type_distribution: Record<string, number>;
  migration_priority_distribution: Record<string, number>;
  certificate_expiry_distribution: Record<string, number>;
}

export interface CbomComponent {
  id: string;
  type: string;
  algorithm: string | null;
  key_size: number | null;
  purpose: string;
  location: string;
  component: string;
  confidence: number;
  business_asset: string | null;
  quantum_security: string;
  risk_score: number | null;
}
