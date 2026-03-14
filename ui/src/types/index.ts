export interface Provider {
  id: number
  name: string
  type: string
  api_endpoint: string
  token?: string
  config: Record<string, string>
  created_at: number
  updated_at: number
}

export interface ProviderCreate {
  name: string
  type: string
  api_endpoint: string
  token: string
  config?: Record<string, string>
}

export interface ProviderUpdate {
  name: string
  api_endpoint: string
  token?: string
  config?: Record<string, string>
}

export interface View {
  id: number
  name: string
  description: string
  provider_ids: number[]
  created_at: number
}

export interface ViewCreate {
  name: string
  description?: string
}

export interface Zone {
  id: number
  name: string
  view_id: number
  deployment_retention: number | null
  manage_soa: boolean
  manage_ns: boolean
  sync_status?: string
  sync_checked_at?: string
  git_repo_id: number | null
  git_branch: string | null
  created_at: number
}

export interface ZoneCreate {
  name: string
  view_id: number
  deployment_retention?: number | null
  manage_soa?: boolean
  manage_ns?: boolean
  git_repo_id?: number | null
  git_branch?: string | null
}

export interface DnsRecord {
  id: number
  zone_id: number
  name: string
  type: string
  ttl: number
  value_template: string
  priority: number
  provider_meta: Record<string, unknown> | null
  last_audit_id: number | null
  pending_delete: boolean
  created_at: number
  updated_at: number
}

export interface RecordCreate {
  name: string
  type: string
  ttl?: number
  value_template: string
  priority?: number
  provider_meta?: Record<string, unknown>
}

export interface Variable {
  id: number
  name: string
  value: string
  type: string
  scope: string
  zone_id: number | null
  created_at: number
  updated_at: number
}

export interface VariableCreate {
  name: string
  value: string
  type: string
  scope?: string
  zone_id?: number | null
}

export interface RecordDiff {
  action: 'add' | 'update' | 'delete' | 'drift'
  name: string
  type: string
  source_value: string
  provider_value: string
  ttl: number
  priority: number
}

export interface DriftAction {
  name: string
  type: string
  action: 'adopt' | 'delete' | 'ignore'
}

export interface ProviderPreview {
  provider_id: number
  provider_name: string
  provider_type: string
  has_drift: boolean
  diffs: RecordDiff[]
}

export interface PreviewResult {
  zone_id: number
  zone_name: string
  has_drift: boolean
  diffs: RecordDiff[]
  providers?: ProviderPreview[]
}

export interface DeploymentSnapshot {
  id: number
  zone_id: number
  deployed_by: number
  deployed_at: number
  seq: number
  snapshot: Record<string, unknown>
}

export interface DeploymentDiff {
  deployment_id: number
  zone_id: number
  diffs: {
    action: 'added' | 'removed' | 'changed'
    record?: Record<string, unknown>
    current?: Record<string, unknown>
    snapshot?: Record<string, unknown>
  }[]
}

export interface AuditEntry {
  id: number
  entity_type: string
  operation: string
  identity: string
  timestamp: string
  entity_id: number
  old_value: Record<string, unknown> | null
  new_value: Record<string, unknown> | null
  variable_used: string | null
  auth_method: string
  ip_address: string
}

export interface User {
  user_id: number
  username: string
  email: string
  role: string
  permissions: string[]
  auth_method: string
  force_password_change: boolean
}

export interface ApiError {
  error: string
  message: string
}

export interface PurgeResult {
  deleted: number
  oldest_remaining: string | null
}

export interface UserDetail {
  id: number
  username: string
  email: string
  auth_method: string
  is_active: boolean
  force_password_change: boolean
  groups: { id: number; name: string }[]
}

export interface Group {
  id: number
  name: string
  description: string
  member_count: number
}

export interface GroupMember {
  user_id: number
  username: string
  role_id: number
  role_name: string
  scope_type?: string
  scope_id?: number
}

export interface GroupDetail extends Group {
  members: GroupMember[]
}

export interface Role {
  id: number
  name: string
  description: string
  is_system: boolean
  permissions: string[]
  created_at: string
}

export interface RoleCreate {
  name: string
  description: string
  permissions?: string[]
}

export interface PermissionCategory {
  name: string
  permissions: string[]
}

export interface ApiKeyEntry {
  id: number
  description: string
  prefix: string
  user_id: number
  created_at: string
  expires_at: string | null
  last_used_at: string | null
}

export interface ProviderHealth {
  id: number
  name: string
  type: string
  status: 'healthy' | 'unreachable' | 'error'
  message: string
}

export interface ZoneSyncResult {
  zone_id: number
  sync_status: string
  sync_checked_at?: string
  server_time?: number
}

export interface SystemSetting {
  key: string
  value: string
  description: string
  default: string
  restart_required: boolean
  updated_at: string
}

export interface IdentityProvider {
  id: number
  name: string
  type: 'oidc' | 'saml'
  is_enabled: boolean
  config: Record<string, unknown>
  has_secret: boolean
  group_mappings: GroupMappingRules | null
  default_group_id: number | null
  created_at: string
  updated_at: string
}

export interface GroupMappingRule {
  idp_group: string
  meridian_group_id: number
}

export interface GroupMappingRules {
  rules: GroupMappingRule[]
}

export interface IdentityProviderCreate {
  name: string
  type: 'oidc' | 'saml'
  config: Record<string, unknown>
  client_secret?: string
  group_mappings?: GroupMappingRules
  default_group_id?: number
}

export interface IdentityProviderUpdate {
  name: string
  is_enabled: boolean
  config: Record<string, unknown>
  client_secret?: string
  group_mappings?: GroupMappingRules
  default_group_id?: number
}

export interface IdpTestResult {
  redirect_url: string
}

export interface IdpClaimsResult {
  subject: string
  email: string
  username: string
  groups: string[]
  all_claims: Record<string, unknown>
}

export interface EnabledIdp {
  id: number
  name: string
  type: 'oidc' | 'saml'
}

export interface GitRepo {
  id: number
  name: string
  remote_url: string
  auth_type: 'ssh' | 'https' | 'none'
  has_credentials: boolean
  default_branch: string
  local_path: string
  known_hosts: string
  is_enabled: boolean
  last_sync_at: string | null
  last_sync_status: string | null
  last_sync_error: string | null
  created_at: string
  updated_at: string
}

export interface GitRepoCreate {
  name: string
  remote_url: string
  auth_type: 'ssh' | 'https' | 'none'
  credentials?: string
  default_branch?: string
  local_path?: string
  known_hosts?: string
}

export interface GitRepoUpdate {
  name: string
  remote_url: string
  auth_type: 'ssh' | 'https' | 'none'
  credentials?: string
  default_branch?: string
  local_path?: string
  known_hosts?: string
  is_enabled?: boolean
}
