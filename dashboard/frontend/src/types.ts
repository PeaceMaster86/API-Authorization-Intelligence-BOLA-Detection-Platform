export type Finding = {
  finding_id: string;
  title: string;
  severity: string;
  endpoint: string;
  method: string;
  principal: string;
  object_id: string;
  verification_result: string;
  confidence: number;
  evidence: string;
  remediation: string;
};

export type Report = {
  summary: {
    total: number;
    confirmed: number;
    severity: Record<string, number>;
  };
  findings: Finding[];
};

export type Endpoint = {
  path: string;
  method: string;
  object_parameters: string[];
  testing_capability: string;
};

export type ObjectRecord = {
  object_id: string;
  resource_type: string;
  owner: string;
  tenant_id: string;
  visibility: string;
  shared_with: string[];
};
